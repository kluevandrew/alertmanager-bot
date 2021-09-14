package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	env "github.com/caarlos0/env/v6"
	"github.com/docker/libkv/store"
	"github.com/docker/libkv/store/boltdb"
	"github.com/docker/libkv/store/consul"
	"github.com/docker/libkv/store/etcd"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/metalmatze/alertmanager-bot/pkg/alertmanager"
	"github.com/metalmatze/alertmanager-bot/pkg/telegram"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	storeBolt   = "bolt"
	storeConsul = "consul"
	storeEtcd   = "etcd"

	levelDebug = "debug"
	levelInfo  = "info"
	levelWarn  = "warn"
	levelError = "error"
)

var (
	// Version of alertmanager-bot.
	Version string
	// Revision or Commit this binary was built from.
	Revision string
	// GoVersion running this binary.
	GoVersion = runtime.Version()
	// StartTime has the time this was started.
	StartTime = time.Now()
)

var cli struct {
	AlertmanagerURL string   `env:"ALERTMANAGER_URL" envDefault:"http://localhost:9093/" help:"The URL that's used to connect to the alertmanager"`
	ListenAddr      string   `env:"LISTEN_ADDR" envDefault:"0.0.0.0:8080" help:"The address the alertmanager-bot listens on for incoming webhooks"`
	LogJSON         bool     `env:"LOG_JSON" envDefault:"false" help:"Tell the application to log json and not key value pairs"`
	LogLevel        string   `env:"LOG_LEVEL" envDefault:"info" enum:"error,warn,info,debug" help:"The log level to use for filtering logs"`
	TemplatePaths   []string `env:"TEMPLATE_PATHS" envDefault:"/templates/default.tmpl" help:"The paths to the template"`

	TelegramAdmins []int  `required:"true" env:"TELEGRAM_ADMIN" help:"The ID of the initial Telegram Admin"`
	TelegramToken  string `required:"true" env:"TELEGRAM_TOKEN" help:"The token used to connect with Telegram"`

	Store       string `env:"STORE" required:"true"  enum:"bolt,consul,etcd" help:"The store to use"`
	StorePrefix string `env:"STORE_KEY_PREFIX" envDefault:"telegram/chats" help:"Prefix for store keys"`

	EtcdURL                   string `env:"ETCD_URL" default:"localhost:2379" help:"The URL that's used to connect to the etcd store"`
	EtcdTLSInsecure           bool   `env:"ETCD_TLS_INSECURE" default:"false" help:"Use TLS or not"`
	EtcdTLSInsecureSkipVerify bool   `env:"ETCD_TLS_INSECURE_SKIP_VERIFY" default:"false" help:"Skip server certificates verification"`
	EtcdTLSCert               string `env:"ETCD_TLS_CERT" type:"path" help:"Path to the TLS cert file"`
	EtcdTLSKey                string `env:"ETCD_TLS_KEY" type:"path" help:"Path to the TLS key file"`
	EtcdTLSCA                 string `env:"ETCD_TLS_CA" type:"path" help:"Path to the TLS trusted CA cert file"`

	ConsulURL string `env:"CONSUL_URL" envDefault:"localhost:8500" help:"The URL that's used to connect to the consul store"`

	BoltPath string `env:"BOLT_PATH" type:"path" envDefault:"/tmp/bot.db" help:"The path to the file where bolt persists its data"`
}

func main() {
	if err := env.Parse(&cli); err != nil {
		panic(fmt.Sprintf("Error parse env: %+v\n", err))
	}
	var err error

	levelFilter := map[string]level.Option{
		levelError: level.AllowError(),
		levelWarn:  level.AllowWarn(),
		levelInfo:  level.AllowInfo(),
		levelDebug: level.AllowDebug(),
	}

	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	if cli.LogJSON {
		logger = log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
	}

	logger = level.NewFilter(logger, levelFilter[cli.LogLevel])
	logger = log.With(logger,
		"ts", log.DefaultTimestampUTC,
		"caller", log.DefaultCaller,
	)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	alertmanagerURL, err := url.Parse(cli.AlertmanagerURL)
	if err != nil {
		level.Error(logger).Log("msg", "failed to parse alertmanager url", "err", err)
		os.Exit(1)
	}

	var am *alertmanager.Client
	{
		client, err := alertmanager.NewClient(alertmanagerURL)
		if err != nil {
			level.Error(logger).Log("msg", "failed to create alertmanager client", "err", err)
			os.Exit(1)
		}
		am = client
	}

	var kvStore store.Store
	{
		switch strings.ToLower(cli.Store) {
		case storeBolt:
			kvStore, err = boltdb.New([]string{cli.BoltPath}, &store.Config{Bucket: "alertmanager"})
			if err != nil {
				level.Error(logger).Log("msg", "failed to create bolt store backend", "err", err)
				os.Exit(1)
			}
		case storeConsul:
			kvStore, err = consul.New([]string{cli.ConsulURL}, nil)
			if err != nil {
				level.Error(logger).Log("msg", "failed to create consul store backend", "err", err)
				os.Exit(1)
			}
		case storeEtcd:
			tlsConfig := &tls.Config{}

			if cli.EtcdTLSCert != "" {
				cert, err := tls.LoadX509KeyPair(cli.EtcdTLSCert, cli.EtcdTLSKey)
				if err != nil {
					level.Error(logger).Log("msg", "failed to create etcd store backend, could not load certificates", "err", err)
					os.Exit(1)
				}
				tlsConfig.Certificates = []tls.Certificate{cert}
			}

			if cli.EtcdTLSCA != "" {
				caCert, err := ioutil.ReadFile(cli.EtcdTLSCA)
				if err != nil {
					level.Error(logger).Log("msg", "failed to create etcd store backend, could not load ca certificate", "err", err)
					os.Exit(1)
				}

				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(caCert)
				tlsConfig.RootCAs = caCertPool
			}

			tlsConfig.InsecureSkipVerify = cli.EtcdTLSInsecureSkipVerify

			if !cli.EtcdTLSInsecure {
				kvStore, err = etcd.New([]string{cli.EtcdURL}, &store.Config{TLS: tlsConfig})
			} else {
				kvStore, err = etcd.New([]string{cli.EtcdURL}, nil)
			}

			if err != nil {
				level.Error(logger).Log("msg", "failed to create etcd store backend", "err", err)
				os.Exit(1)
			}
		default:
			level.Error(logger).Log("msg", "please provide one of the following supported store backends: bolt, consul, etcd")
			os.Exit(1)
		}
	}
	defer kvStore.Close()

	ctx, cancel := context.WithCancel(context.Background())

	// TODO Needs fan out for multiple bots
	webhooks := make(chan alertmanager.TelegramWebhook, 32)

	var g run.Group
	{
		tlogger := log.With(logger, "component", "telegram")

		commandCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "alertmanagerbot_commands_total",
			Help: "Number of commands received by command name",
		}, []string{"command"})
		reg.MustRegister(commandCounter)

		commandCount := func(command string) {
			commandCounter.WithLabelValues(command).Inc()
		}

		chats, err := telegram.NewChatStore(kvStore, cli.StorePrefix)
		if err != nil {
			level.Error(logger).Log("msg", "failed to create chat store", "err", err)
			os.Exit(1)
		}

		bot, err := telegram.NewBot(
			chats, cli.TelegramToken, cli.TelegramAdmins[0],
			telegram.WithLogger(tlogger),
			telegram.WithCommandEvent(commandCount),
			telegram.WithAddr(cli.ListenAddr),
			telegram.WithAlertmanager(am),
			telegram.WithTemplates(alertmanagerURL, cli.TemplatePaths...),
			telegram.WithRevision(Revision),
			telegram.WithStartTime(StartTime),
			telegram.WithExtraAdmins(cli.TelegramAdmins[1:]...),
		)
		if err != nil {
			level.Error(tlogger).Log("msg", "failed to create bot", "err", err)
			os.Exit(2)
		}

		g.Add(func() error {
			level.Info(tlogger).Log(
				"msg", "starting alertmanager-bot",
				"version", Version,
				"revision", Revision,
				"goVersion", GoVersion,
			)

			// Runs the bot itself communicating with Telegram
			return bot.Run(ctx, webhooks)
		}, func(err error) {
			cancel()
		})
	}
	{
		wlogger := log.With(logger, "component", "webserver")

		// TODO: Use Heptio's healthcheck library
		handleHealth := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}

		webhooksCounter := prometheus.NewCounter(prometheus.CounterOpts{
			Name: "alertmanagerbot_webhooks_total",
			Help: "Number of webhooks received by this bot",
		})

		reg.MustRegister(webhooksCounter)

		m := http.NewServeMux()
		m.HandleFunc("/webhooks/telegram/", alertmanager.HandleTelegramWebhook(wlogger, webhooksCounter, webhooks))
		m.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		m.HandleFunc("/health", handleHealth)
		m.HandleFunc("/healthz", handleHealth)

		s := http.Server{
			Addr:    cli.ListenAddr,
			Handler: m,
		}

		g.Add(func() error {
			level.Info(wlogger).Log("msg", "starting webserver", "addr", cli.ListenAddr)
			return s.ListenAndServe()
		}, func(err error) {
			_ = s.Shutdown(context.Background())
		})
	}
	{
		sig := make(chan os.Signal)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

		g.Add(func() error {
			<-sig
			return nil
		}, func(err error) {
			cancel()
			close(sig)
		})
	}

	if err := g.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
