package secret_store

//noinspection GoUnusedConst
const (
	ProtectionKeyDefault = "Software:Default"
	ProtectionKeyNull    = "Null:Null"
)

type SecretStoreResult int

//go:generate stringer -type=SecretStoreResult
//noinspection GoUnusedConst
const (
	Success SecretStoreResult = iota
	InvalidCallingAssembly
	CreateDatabaseError
	UseDatabaseError
	CreateTableError
	CreateIndexError
	ConnectionError
	TransactionError
	InvalidVaultID
	InvalidParams
	InsufficientPermissions
	CryptoFailure
	DeleteSecretFailed
	AddSecretFailed
	RetrieveSecretFailed
	RetrieveSecretTypeFailed
	GetNextVaultIDFailed
	DisassociateFailed
	OwnerLookupFailed
	AssociateDataFailed
	LookupFailed
	InvalidKey
	QueryError
	SecurityGroupNotImplemented
)


