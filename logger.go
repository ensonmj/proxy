package proxy

import "github.com/sirupsen/logrus"

var (
	log = logrus.New()
)

func SetLevel(lvl uint32) {
	log.SetLevel(logrus.Level(lvl))
}

func AddHook(hook logrus.Hook) {
	log.AddHook(hook)
}
