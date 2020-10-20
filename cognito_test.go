package cognito

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"testing"
)

func getToken() (token string, err error) {
	var buffer bytes.Buffer
	json.NewEncoder(&buffer).Encode(map[string]string{
		"username": "",
		"password": "",
	})

	resp, err := http.Post("", "", &buffer)
	if err != nil {
		return token, err
	}
	defer resp.Body.Close()

	data := make(map[string]interface{})
	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return token, err
	}

	if token, exists := data["id_token"]; exists {
		return token.(string), nil
	}

	return token, err
}
func TestCognito(t *testing.T) {
	token, err := getToken()
	log.Println(token)
	if err != nil {
		t.Fail()
	}

	cog := New(Config{
		Region:     "",
		UserPoolID: "",
		AppID:      "",
	})

	t.Run("ParseJWT", func(t *testing.T) {
		if _, _, valid := cog.ParseJWT(token); !valid {
			t.Fail()
		}
	})

	t.Run("Invalid JWT", func(t *testing.T) {
		if _, _, valid := cog.ParseJWT("0" + token); valid {
			t.Fail()
		}
	})

	t.Run("Authorized", func(t *testing.T) {
		if !cog.Authorized(token) {
			t.Fail()
		}
	})

	t.Run("Unauthorized", func(t *testing.T) {
		if cog.Authorized("0" + token) {
			t.Fail()
		}
	})

	t.Run("Handler", func(t *testing.T) {
		if cog.Authorized("0" + token) {
			t.Fail()
		}
	})
}
