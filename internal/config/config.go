package config

var (
	BackendURL  = "dns:///localhost:443"
	RedirectURI = "http://127.0.0.1:8888/callback"
	Version     = "0.0.0"
)

type AppConfig struct {
	BackendURL  string
	RedirectURI string
	Version     string
}

func Load() AppConfig {
	return AppConfig{
		BackendURL:  BackendURL,
		RedirectURI: RedirectURI,
		Version:     Version,
	}
}
