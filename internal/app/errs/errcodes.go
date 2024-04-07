package errs

const (
	Unknown = iota + 0
	MaintenanceMode
	InternalProcessingError
	TaskCreationError
	EncodingJSONError
	DecodingJSONError
	RedisError
	RedisNotFoundError
	SessionExpired
	AccessDenied
	TemporaryBlocked
	InvalidInputData
	URLDecodeError
	UserGettingError
	UserAlreadyExists
	CreateUserError
	GettingUserNotificationError
	CreateUserNotificationError
	EmailConfirmationError
	JwtTokenCreationError
	InvalidNotificationCode
	TokenMismatch
	PasswordUpdateError
	SubscriptionValidationError
	OAuthUserInfoGettingError
	OAuthUserLoginError
	CreateUserProfileError
	FindUserProfileError
	GenerateRefreshTokenError
	RefreshTokenFailed
)
