package exception

const EmptyParameter = "8"
const EmptyParameterMsg = "Parameter $param should not be empty"

const BadRequestBody = "10"
const BadRequestBodyMsg = "Failed to decode body"

const RequiredParamsMissing = "15"
const RequiredParamsMissingMsg = "Required parameters are missing: $params"

const ApiKeyNotFound = "83"
const ApiKeyNotFoundMsg = "Api key for user $user and integration $integration not found"

// UnableToStartCapture capture codes and messages
const UnableToStartCapture = "20000"
const UnableToStartCaptureMsg = "unable to start capture"
const UnableToStopCapture = "20001"
const UnableToStopCaptureMsg = "unable to stop capture"
const UnableToListInterfaces = "20002"
const UnableToListInterfacesMsg = "unable to list network interfaces"
const UnableToListAddresses = "20003"
const UnableToListAddressesMsg = "unable to get local address list"
