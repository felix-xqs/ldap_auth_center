package conf
import (
	"github.com/felix-xqs/golog"
	"github.com/gin-gonic/gin"
)
type Conf struct {
	// 基本配置
	App *struct {
		Name string `mapstructure:"name"`
		Port int    `mapstructure:"port"`
		Env  string `mapstructure:"env"`
	} `mapstructure:"app"`

	Log  *golog.Config  `mapstructure:"log"`
}

var (
	Gin *gin.Engine
	C Conf
)

func initGin(){
	Gin = gin.New()
}
func init(){
	initGin()
}