package config

type Configuration struct {
	Listen          string `json:"listen"`
	ServiceName     string `json:"servicename"`
	ServiceFullName string `json:"servicefullname"`
}
