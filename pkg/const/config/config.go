package config

//noinspection GoUnusedConst
const (
	ClassX509Certificate = "X509 Certificate"
	ClassPolicy          = "Policy"
	ClassOpenSSLCA       = "OpenSSL CA"
	ClassSelfSignedCA    = "Self Signed CA"
)

//noinspection GoUnusedConst
const (
	DriverSelfSigned = "caselfsigned"
	DriverOpenSSL    = "caopenssl"
)

type ConfigResult int

//go:generate stringer -type=ConfigResult
//noinspection GoUnusedConst
const (
	Success                         ConfigResult = 1
	InvalidArgument                              = 2
	InvalidArgumentRange                         = 3
	MismatchedArguments                          = 4
	NotImplemented                               = 5
	InvalidDestinationList                       = 6
	InsufficientPrivileges                       = 7
	InvalidOperation                             = 8
	UnexpectedAssemblyError                      = 9
	OutOfMemory                                  = 10
	AttributeDoesNotExist                        = 100
	AttributeAlreadyExists                       = 101
	AttributeNotFound                            = 102
	AttributeValueExists                         = 103
	AttributeStillInUse                          = 104
	AttributeNameTooLong                         = 105
	AttributeReferenceDoesNotExist               = 106
	AttributeSyntaxCollision                     = 107
	AttributePropertyCollision                   = 108
	CannotRemoveMandatory                        = 109
	AttributeValueIsMandatory                    = 110
	AttributeValueTooLong                        = 111
	IllegalAttributeForClass                     = 112
	InvalidAttributeDN                           = 113
	AttributeValueDoesNotExist                   = 114
	AttributeIsSingleValued                      = 115
	AttributeIsReadOnly                          = 116
	AttributeIsHidden                            = 117
	ClassDoesNotExist                            = 200
	ClassAlreadyExists                           = 201
	ClassStillInUse                              = 202
	ClassNameTooLong                             = 203
	ClassInvalidSuperClass                       = 204
	ClassInvalidContainmentClass                 = 205
	ClassInvalidNamingAttribute                  = 206
	ClassInvalidMandatoryAttribute               = 207
	ClassInvalidOptionalAttribute                = 208
	ClassInvalidName                             = 209
	ClassInvalidContainmentSubClass              = 210
	PolicyDoesNotExist                           = 300
	PolicyLockStateCollision                     = 301
	LockNameAlreadyExists                        = 350
	LockNameDoesNotExist                         = 351
	LockNameOwnedByAnother                       = 352
	LockNameLimitReached                         = 353
	LockNameAttemptTimedOut                      = 354
	ObjectDoesNotExist                           = 400
	ObjectAlreadyExists                          = 401
	ObjectHasChildren                            = 402
	ObjectNameTooLong                            = 403
	ObjectDepthTooDeep                           = 404
	ObjectInvalidName                            = 405
	ObjectInvalidClass                           = 406
	ObjectInvalidContainment                     = 407
	ObjectMandatoryMissing                       = 408
	ObjectIsReadOnly                             = 409
	ObjectInvalidOperation                       = 410
	DriverMissingDSN                             = 500
	DriverMissingDatabaseName                    = 501
	DriverDatabaseError                          = 502
	DriverTransactionError                       = 503
	DriverTransactionCollision                   = 504
	DriverGenerationUpdateError                  = 505
	CacheLockException                           = 600
	CacheEntryNotFound                           = 601
	CacheEntryAlreadyExists                      = 602
	CacheEntryIsSuperior                         = 603
	CacheEntryIsIncompatible                     = 604
	XmlInvalidStructure                          = 700
	XmlMissingNaming                             = 701
	XmlMissingSyntax                             = 702
	XmlMissingProperty                           = 703
	XmlUnknownElementAttribute                   = 704
)
