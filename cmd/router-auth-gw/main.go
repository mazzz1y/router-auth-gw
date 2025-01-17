package main

import (
	"os"
	"sync"

	"github.com/mazzz1y/router-auth-gw/internal/config"
	"github.com/mazzz1y/router-auth-gw/internal/device"
	"github.com/mazzz1y/router-auth-gw/internal/entrypoint"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

var version = "custom"

func main() {
	app := &cli.App{
		Name:    "router-auth-gw",
		Usage:   "Proxy Gateway for Keenetic Routers",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				EnvVars: []string{"CONFIG_PATH"},
				Value:   "config.yaml",
				Usage:   "path to configuration file",
			},
			&cli.StringFlag{
				Name:    "log-level",
				EnvVars: []string{"LOG_LEVEL"},
				Value:   "info",
				Usage:   "Logging level (e.g. debug, info, warn, error, fatal, panic, no)",
			},
			&cli.StringFlag{
				Name:    "log-type",
				EnvVars: []string{"LOG_TYPE"},
				Value:   "pretty",
				Usage:   "Logging format/type (e.g. pretty, json)",
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "start",
				Usage:  "start proxy servers based on config",
				Action: startServersAction,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("failed to start")
	}
}

func startServersAction(c *cli.Context) error {
	configPath := c.String("config")
	logLevel := c.String("log-level")
	logType := c.String("log-type")

	setLogLevel(logLevel, logType)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return err
	}

	dm, err := device.NewDeviceManager(cfg.Devices, true)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, entryCfg := range cfg.Entrypoints {
		wg.Add(1)
		go startServer(dm, entryCfg, &wg)
	}

	wg.Wait()
	return nil
}

func startServer(dm *device.DeviceManager, entryCfg config.EntrypointConfig, wg *sync.WaitGroup) {
	defer wg.Done()

	d, ok := dm.Devices[entryCfg.DeviceTag]
	if !ok {
		log.Fatal().Msgf("%s: \"%s\" device not found", entryCfg.Listen, entryCfg.DeviceTag)
	}

	err := entrypoint.NewEntrypoint(entrypoint.EntrypointOptions{
		Device:              d,
		ListenAddr:          entryCfg.Listen,
		ForwardAuthHeader:   entryCfg.ForwardAuth.Header,
		ForwardAuthMapping:  entryCfg.ForwardAuth.Mapping,
		BasicAuth:           entryCfg.BasicAuthMap(),
		AllowedEndpoints:    entryCfg.AllowedEndpoints,
		BypassAuthEndpoints: entryCfg.BypassAuthEndpoints,
		OnlyGet:             entryCfg.ReadOnly,
	}).Start()

	if err != nil {
		log.Fatal().Err(err).Msg("failed to start entrypoint")
	}
}

func setLogLevel(logLevel string, logType string) {
	switch logType {
	case "json":
	case "pretty":
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	default:
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		log.Info().Msgf("invalid log type: %s. using 'pretty' as default", logType)
	}

	switch logLevel {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	case "no":
		zerolog.SetGlobalLevel(zerolog.NoLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		log.Info().Msgf("invalid log level: %s. using 'info' as default", logLevel)
	}
}
