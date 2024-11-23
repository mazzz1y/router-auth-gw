package main

import (
	"github.com/mazzz1y/keenetic-auth-gw/internal/config"
	"github.com/mazzz1y/keenetic-auth-gw/internal/devices"
	"github.com/mazzz1y/keenetic-auth-gw/internal/entrypoint"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"sync"
)

var version = "custom"

func main() {
	app := &cli.App{
		Name:    "keenetic-auth-gw",
		Usage:   "Proxy Gateway for Keenetic Routers",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				EnvVars: []string{"CONFIG_PATH"},
				Value:   "config.yaml",
				Usage:   "path to configuration file",
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
		log.Fatal(err)
	}
}

func startServersAction(c *cli.Context) error {
	configPath := c.String("config")
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return err
	}

	dm, err := devices.NewDeviceManager(cfg.Devices, true)
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

func startServer(dm *devices.DeviceManager, entryCfg config.EntrypointConfig, wg *sync.WaitGroup) {
	defer wg.Done()

	device, ok := dm.GetDeviceByTag(entryCfg.DeviceTag)
	if !ok {
		log.Fatalf("%s: \"%s\" device not found", entryCfg.Listen, entryCfg.DeviceTag)
	}

	err := entrypoint.NewEntrypoint(entrypoint.EntrypointOptions{
		Device:            device,
		ListenAddr:        entryCfg.Listen,
		ForwardAuthHeader: entryCfg.ForwardedAuthHeader,
		BasicAuth:         entryCfg.BasicAuthMap(),
		AllowedEndpoints:  entryCfg.AllowedEndpoints,
		OnlyGet:           entryCfg.ReadOnly,
	}).Start()

	if err != nil {
		log.Fatalf("error running entrypoint %v: %v", entryCfg, err)
	}
}
