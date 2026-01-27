// Package main provides a CLI for monitoring CertStream events.
// It supports filtering by domains, verbose output, and graceful shutdown.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jonasbg/certstream-monitor/certstream"
	"github.com/jonasbg/certstream-monitor/internal/config"
	"github.com/jonasbg/certstream-monitor/internal/output"
	"github.com/jonasbg/certstream-monitor/internal/webhook"
)

// main parses command-line flags, configures the CertStream monitor, and handles events.
func main() {
	// Parse configuration from flags and environment
	cfg := config.ParseFromFlags()

	// Create output formatter
	formatter := output.NewFormatter(cfg.URLsOnly, cfg.Verbose)

	// Print startup information with all configuration
	wsURL := cfg.WebSocketURL
	if wsURL == "" {
		wsURL = ""
	}
	formatter.PrintStartupInfo(
		cfg.Domains,
		wsURL,
		certstream.DefaultWebSocketURL,
		cfg.WebhookURL,
		cfg.ReconnectTimeoutSec,
		cfg.MaxReconnectTimeoutSec,
		cfg.NoBackoff,
		cfg.BufferSize,
		cfg.WorkerCount,
		cfg.StatsIntervalSec,
		cfg.APIToken,
	)

	// Create webhook client if configured
	var webhookClient *webhook.Client
	var missingWebhook, missingAPIToken bool
	if cfg.HasWebhook() {
		webhookClient = webhook.NewClient(cfg.WebhookURL, cfg.APIToken)
		if cfg.APIToken == "" {
			missingAPIToken = true
		}
	} else {
		missingWebhook = true
	}

	// Build monitor options
	options := buildMonitorOptions(cfg)

	// Create and start the monitor
	monitor := certstream.New(options...)
	monitor.Start()

	eventQueueSize := minInt(cfg.BufferSize, 10000)
	eventQueue := make(chan certstream.CertEvent, eventQueueSize)
	var droppedEvents uint64

	var webhookDispatcher *webhookDispatcher
	if webhookClient != nil {
		webhookDispatcher = newWebhookDispatcher(context.Background(), webhookClient, maxInt(1, cfg.WorkerCount), eventQueueSize)
	}

	var outputWG sync.WaitGroup
	var warnWebhookOnce, warnAPITokenOnce sync.Once
	outputWG.Add(1)
	go func() {
		defer outputWG.Done()
		for event := range eventQueue {
			formatter.FormatEvent(event)
			if len(event.MatchedDomains) > 0 {
				if missingWebhook {
					warnWebhookOnce.Do(func() {
						log.Printf("WARNING: Domain matched but WEBHOOK_URL is not set - notifications will not be sent")
					})
				} else if missingAPIToken {
					warnAPITokenOnce.Do(func() {
						log.Printf("WARNING: Domain matched but API_TOKEN is not set - webhook requests may fail authentication")
					})
				}
				if webhookDispatcher != nil {
					webhookDispatcher.enqueue(event)
				}
			}
		}
	}()

	if cfg.StatsIntervalSec > 0 {
		interval := cfg.StatsInterval()
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			prev := monitor.Stats()
			for range ticker.C {
				current := monitor.Stats()
				currentOutputDropped := atomic.LoadUint64(&droppedEvents)

				intervalSeconds := interval.Seconds()
				rawRate := float64(current.RawReceived-prev.RawReceived) / intervalSeconds
				decodeRate := float64(current.CertsDecoded-prev.CertsDecoded) / intervalSeconds
				eventRate := float64(current.EventsSent-prev.EventsSent) / intervalSeconds

				log.Printf(
					"Stats: raw=%d (+%.0f/s) dropped=%d rawQ=%d/%d decoded=%d (+%.0f/s) prefilter hit=%d skip=%d events=%d (+%.0f/s) evDrop=%d outQ=%d/%d outDrop=%d",
					current.RawReceived,
					rawRate,
					current.RawDropped,
					current.RawQueueLen,
					current.RawQueueCap,
					current.CertsDecoded,
					decodeRate,
					current.PrefilterHits,
					current.PrefilterSkips,
					current.EventsSent,
					eventRate,
					current.EventsDropped,
					len(eventQueue),
					cap(eventQueue),
					currentOutputDropped,
				)

				prev = current
			}
		}()
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Process certificates
	for {
		select {
		case event := <-monitor.Events():
			select {
			case eventQueue <- event:
			default:
				dropped := atomic.AddUint64(&droppedEvents, 1)
				if dropped%1000 == 1 {
					log.Printf("Output backlog, dropping events. Dropped: %d\n", dropped)
				}
			}

		case <-sigChan:
			formatter.PrintShutdown()
			monitor.Stop()
			close(eventQueue)
			outputWG.Wait()
			if webhookDispatcher != nil {
				webhookDispatcher.closeAndWait()
			}
			return
		}
	}
}

// buildMonitorOptions creates monitor options from configuration
func buildMonitorOptions(cfg *config.CLIConfig) []certstream.Option {
	options := []certstream.Option{
		certstream.WithDebug(cfg.Verbose),
		certstream.WithReconnectTimeout(cfg.ReconnectTimeout()),
		certstream.WithMaxReconnectTimeout(cfg.MaxReconnectTimeout()),
		certstream.WithDisableBackoff(cfg.NoBackoff),
		certstream.WithBufferSize(cfg.BufferSize),
		certstream.WithWorkerCount(cfg.WorkerCount),
	}

	if cfg.HasDomains() {
		options = append(options, certstream.WithDomains(cfg.Domains))
	}

	if cfg.WebSocketURL != "" {
		options = append(options, certstream.WithWebSocketURL(cfg.WebSocketURL))
	}

	return options
}

type webhookJob struct {
	event  certstream.CertEvent
	domain string
}

type webhookDispatcher struct {
	jobs    chan webhookJob
	wg      sync.WaitGroup
	client  *webhook.Client
	ctx     context.Context
	dropped uint64
	errors  uint64
}

func newWebhookDispatcher(ctx context.Context, client *webhook.Client, workers, queueSize int) *webhookDispatcher {
	dispatcher := &webhookDispatcher{
		jobs:   make(chan webhookJob, queueSize),
		client: client,
		ctx:    ctx,
	}

	for i := 0; i < workers; i++ {
		dispatcher.wg.Add(1)
		go func() {
			defer dispatcher.wg.Done()
			for job := range dispatcher.jobs {
				if err := dispatcher.client.Send(dispatcher.ctx, job.event, job.domain); err != nil {
					errCount := atomic.AddUint64(&dispatcher.errors, 1)
					if errCount == 1 || errCount%100 == 0 {
						log.Printf("WARNING: Webhook error (total errors: %d): %v", errCount, err)
					}
				}
			}
		}()
	}

	return dispatcher
}

func (d *webhookDispatcher) enqueue(event certstream.CertEvent) {
	for _, certDomain := range event.Certificate.Data.LeafCert.AllDomains {
		for _, watchDomain := range event.MatchedDomains {
			if certstream.IsDomainMatch(certDomain, watchDomain) {
				select {
				case d.jobs <- webhookJob{event: event, domain: certDomain}:
				default:
					dropped := atomic.AddUint64(&d.dropped, 1)
					if dropped%1000 == 1 {
						log.Printf("Webhook backlog, dropping notifications. Dropped: %d\n", dropped)
					}
				}
				break
			}
		}
	}
}

func (d *webhookDispatcher) closeAndWait() {
	close(d.jobs)
	d.wg.Wait()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
