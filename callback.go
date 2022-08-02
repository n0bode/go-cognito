package cognito

type AuthenticationHandler func(username map[string]interface{}) bool
