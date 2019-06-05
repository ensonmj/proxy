package proxy

import "github.com/sirupsen/logrus"

var (
	log = logrus.New()
)

func SetLevel(lvl int) {
	log.SetLevel(logrus.Level(lvl))
}

func AddHook(hook logrus.Hook) {
	log.AddHook(hook)
}
