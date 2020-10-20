## Middleware cognito para apis(golang)

### Uso

Para utilizar o middleware basta coloca-lo antes de chamar a função da rota 

```golang
package main

import (
	cognito "github.com/n0bode/cognito-golang"
	"net/http"
	"log"
)

func main(){
	cog := cognito.New(
		Region:     "us-west-2",
		UserPoolID: "",
		AppID:      "",
	)
	
	http.HandleFunc("/", cog.Handler(func(w http.ResponseWriter, r *http.Request){
		w.Write([]byte("Hello World"))
	})

	log.Println("Ouvindo na porta :8000")
	if err := http.ListenAndServe(":8000", nil); err != nil{
		log.Error(err)
	}
}
```
