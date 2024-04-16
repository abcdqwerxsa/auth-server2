/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 * openFuyao is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package app

import (
	"context"
	"errors"
	"github.com/spf13/cobra"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"net/http"
	"oauth-server/cmd/oauth-server/app/configs"
	"oauth-server/cmd/oauth-server/app/options"
	"oauth-server/pkg/apiserver"
	"oauth-server/pkg/fuyaoerrors"
	"oauth-server/pkg/zlog"
	"os"
)

// NewOAuthServerCommand is the cobra command for the whole service
func NewOAuthServerCommand() *cobra.Command {
	options := options.NewOAuthServerOption()

	cmd := &cobra.Command{
		Use:   "openfuyao-oauth-server",
		Short: "The authentication server to validate the access token.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := options.Validate(); err != nil {
				zlog.Fatal(err)
			}

			oAuthAPIServerConfigs, err := options.ReadConfig()
			if err != nil {
				zlog.Fatal(err)
			}

			if errs := oAuthAPIServerConfigs.Complete().Validate(); len(errs) != 0 {
				for _, err = range errs {
					zlog.Error(err)
				}
				os.Exit(fuyaoerrors.ErrIntExitSignal)
			}

			return wrapRunOAuthServerServer(oAuthAPIServerConfigs, genericapiserver.SetupSignalContext())
		},
		SilenceUsage: true,
	}

	// Handle flags
	flags := cmd.Flags()

	// Read config path from cli
	flags.StringVar(&options.ConfigFile, "configFile", "", "Location of the authserver configuration file to run from.")

	return cmd
}

func wrapRunOAuthServerServer(c *configs.OAuthServerAPIServerConfig, ctx context.Context) error {
	innerCtx, cancelFunc := context.WithCancel(context.TODO())
	errCh := make(chan error)
	defer close(errCh)
	go func() {
		if err := runOAuthServerServer(c, innerCtx); err != nil {
			errCh <- err
		}
	}()

	// The ctx (signals.SetupSignalHandler()) is to control the entire program life cycle,
	// The ictx(internal context)  is created here to control the life cycle of the ks-apiserver(http httpserver, sharedInformer etc.)
	// when config change, stop httpserver and renew context, start new httpserver
	for {
		select {
		case <-ctx.Done():
			cancelFunc()
			return nil
		//case cfg := <-configCh:
		//	cancelFunc()
		//	s.ConfigFile = &cfg
		//	ictx, cancelFunc = context.WithCancel(context.TODO())
		//	go func() {
		//		if errs := s.Complete().Validate(); len(errs) != 0 {
		//			for _, err := range errs {
		//				errCh <- err
		//			}
		//		}
		//		if err := runOAuthServer(s, ictx); err != nil {
		//			errCh <- err
		//		}
		//	}()
		case err := <-errCh:
			cancelFunc()
			return err
		}
	}
}

func runOAuthServerServer(c *configs.OAuthServerAPIServerConfig, ctx context.Context) error {
	oAuthServerAPIServer, err := apiserver.NewOAuthServerAPIServer(c, ctx.Done())
	if err != nil {
		return err
	}

	err = oAuthServerAPIServer.PrepareRun(ctx.Done())
	if err != nil {
		return err
	}

	err = oAuthServerAPIServer.Run(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return err
}
