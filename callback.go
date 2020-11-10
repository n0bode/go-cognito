package cognito

type AuthenticationHandler func(username string) bool
