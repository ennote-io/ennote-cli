package config

var (
	BackendURL  = "dns:///localhost:443"
	AuthURL     = "https://localhost/cli-login"
	RedirectURI = "http://127.0.0.1:8888/callback"
	Version     = "0.0.0"
)

type AppConfig struct {
	BackendURL  string
	AuthURL     string
	RedirectURI string
	Version     string
}

func Load() AppConfig {
	return AppConfig{
		BackendURL:  BackendURL,
		AuthURL:     AuthURL,
		RedirectURI: RedirectURI,
		Version:     Version,
	}
}
