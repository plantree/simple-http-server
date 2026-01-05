"""Simple HTTP Server package."""

from enum import IntEnum, StrEnum

__version__ = "0.1.0"
__author__ = "Plantree"

__all__ = ["HTTPStatus", "HTTPMethod", "__version__", "__author__"]


class HTTPStatus(IntEnum):
    """HTTP status codes."""

    def __new__(cls, value: int, phrase: str, description: str):
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.phrase = phrase
        obj.description = description
        return obj

    @property
    def is_informational(self) -> bool:
        """Check if the status code is informational (1xx)."""
        return 100 <= self < 200

    @property
    def is_success(self) -> bool:
        """Check if the status code is successful (2xx)."""
        return 200 <= self < 300

    @property
    def is_redirection(self) -> bool:
        """Check if the status code is redirection (3xx)."""
        return 300 <= self < 400

    @property
    def is_client_error(self) -> bool:
        """Check if the status code is client error (4xx)."""
        return 400 <= self < 500

    @property
    def is_server_error(self) -> bool:
        """Check if the status code is server error (5xx)."""
        return 500 <= self < 600

    # informational
    CONTINUE = 100, "Continue", "Request received, please continue"
    SWITCHING_PROTOCOLS = (
        101,
        "Switching Protocols",
        "Switching to new protocol; obey Upgrade header",
    )
    PROCESSING = 102, "Processing", "Server is processing the request"
    EARLY_HINTS = (
        103,
        "Early Hints",
        "Used to return some response headers before final HTTP message",
    )

    # success
    OK = 200, "OK", "The request has succeeded"
    CREATED = (
        201,
        "Created",
        "The request has been fulfilled and resulted in a new resource being created",
    )
    ACCEPTED = (
        202,
        "Accepted",
        "The request has been accepted for processing, but the processing has not been completed",
    )
    NON_AUTHORITATIVE_INFORMATION = (
        203,
        "Non-Authoritative Information",
        "The server successfully processed the request, but is returning information that may be from another source",
    )
    NO_CONTENT = (
        204,
        "No Content",
        "The server successfully processed the request, but is not returning any content",
    )
    RESET_CONTENT = (
        205,
        "Reset Content",
        "The server successfully processed the request, but is not returning any content and requires that the requester reset the document view",
    )
    PARTIAL_CONTENT = (
        206,
        "Partial Content",
        "The server is delivering only part of the resource due to a range header sent by the client",
    )
    MULTI_STATUS = (
        207,
        "Multi-Status",
        "Response contains multiple statuses in the body",
    )
    ALREADY_REPORTED = 208, "Already Reported", "Operation has already been reported"
    IM_USED = 226, "IM Used", "Request completed using instance manipulations"

    # redirection
    MULTIPLE_CHOICES = (
        300,
        "Multiple Choices",
        "Indicates multiple options for the resource from which the client may choose",
    )
    MOVED_PERMANENTLY = (
        301,
        "Moved Permanently",
        "This and all future requests should be directed to the given URI",
    )
    FOUND = 302, "Found", "Tells the client to look at (browse to) another URL"
    SEE_OTHER = (
        303,
        "See Other",
        "The response to the request can be found under another URI using a GET method",
    )
    NOT_MODIFIED = (
        304,
        "Not Modified",
        "Indicates that the resource has not been modified since the version specified by the request headers",
    )
    USE_PROXY = (
        305,
        "Use Proxy",
        "The requested resource is available only through a proxy, the address for which is provided in the response",
    )
    TEMPORARY_REDIRECT = (
        307,
        "Temporary Redirect",
        "In this case, the request should be repeated with another URI; however, future requests can still use the original URI",
    )
    PERMANENT_REDIRECT = (
        308,
        "Permanent Redirect",
        "The request and all future requests should be repeated using another URI",
    )

    # client error
    BAD_REQUEST = (
        400,
        "Bad Request",
        "The server cannot or will not process the request due to an apparent client error",
    )
    UNAUTHORIZED = (
        401,
        "Unauthorized",
        "Authentication is required and has failed or has not yet been provided",
    )
    PAYMENT_REQUIRED = 402, "Payment Required", "Reserved for future use"
    FORBIDDEN = (
        403,
        "Forbidden",
        "The request was valid, but the server is refusing action",
    )
    NOT_FOUND = (
        404,
        "Not Found",
        "The requested resource could not be found but may be available in the future",
    )
    METHOD_NOT_ALLOWED = (
        405,
        "Method Not Allowed",
        "A request method is not supported for the requested resource",
    )
    NOT_ACCEPTABLE = (
        406,
        "Not Acceptable",
        "The requested resource is capable of generating only content not acceptable according to the Accept headers sent in the request",
    )
    PROXY_AUTHENTICATION_REQUIRED = (
        407,
        "Proxy Authentication Required",
        "The client must first authenticate itself with the proxy",
    )
    REQUEST_TIMEOUT = (
        408,
        "Request Timeout",
        "The server timed out waiting for the request",
    )
    CONFLICT = (
        409,
        "Conflict",
        "Indicates that the request could not be processed because of conflict in the request",
    )
    GONE = (
        410,
        "Gone",
        "Indicates that the resource requested is no longer available and will not be available again",
    )
    LENGTH_REQUIRED = (
        411,
        "Length Required",
        "The request did not specify the length of its content, which is required by the requested resource",
    )
    PRECONDITION_FAILED = (
        412,
        "Precondition Failed",
        "The server does not meet one of the preconditions that the requester put on the request",
    )
    PAYLOAD_TOO_LARGE = (
        413,
        "Payload Too Large",
        "The request is larger than the server is willing or able to process",
    )
    REQUEST_ENTITY_TOO_LARGE = (
        413,
        "Request Entity Too Large",
        "The request is larger than the server is willing or able to process",
    )
    URI_TOO_LONG = (
        414,
        "URI Too Long",
        "The URI provided was too long for the server to process",
    )
    UNSUPPORTED_MEDIA_TYPE = (
        415,
        "Unsupported Media Type",
        "The request entity has a media type which the server or resource does not support",
    )
    RANGE_NOT_SATISFIABLE = (
        416,
        "Range Not Satisfiable",
        "The client has asked for a portion of the file, but the server cannot supply that portion",
    )
    EXPECTATION_FAILED = (
        417,
        "Expectation Failed",
        "The server cannot meet the requirements of the Expect request-header field",
    )
    IM_A_TEAPOT = (
        418,
        "I'm a teapot",
        "The server refuses to brew coffee because it is a teapot",
    )
    MISDIRECTED_REQUEST = (
        421,
        "Misdirected Request",
        "The request was directed at a server that is not able to produce a response",
    )
    UNPROCESSIBLE_CONTENT = (
        422,
        "Unprocessable Content",
        "The request was well-formed but was unable to be followed due to semantic errors",
    )
    UNPROCESSIBLE_ENTITY = UNPROCESSIBLE_CONTENT
    LOCKED = 423, "Locked", "The resource that is being accessed is locked"
    FAILED_DEPENDENCY = (
        424,
        "Failed Dependency",
        "The request failed because it depended on another request and that request failed",
    )
    TOO_EARLY = (
        425,
        "Too Early",
        "Indicates that the server is unwilling to risk processing a request that might be replayed",
    )
    UPGRADE_REQUIRED = (
        426,
        "Upgrade Required",
        "The client should switch to a different protocol such as TLS/1.0",
    )
    PRECONDITION_REQUIRED = (
        428,
        "Precondition Required",
        "The origin server requires the request to be conditional",
    )
    TOO_MANY_REQUESTS = (
        429,
        "Too Many Requests",
        "The user has sent too many requests in a given amount of time",
    )
    REQUEST_HEADER_FIELDS_TOO_LARGE = (
        431,
        "Request Header Fields Too Large",
        "The server is unwilling to process the request because its header fields are too large",
    )
    UNAVAILABLE_FOR_LEGAL_REASONS = (
        451,
        "Unavailable For Legal Reasons",
        "The resource requested is unavailable due to legal reasons",
    )

    # server error
    INTERNAL_SERVER_ERROR = (
        500,
        "Internal Server Error",
        "An unexpected condition was encountered",
    )
    NOT_IMPLEMENTED = (
        501,
        "Not Implemented",
        "The server does not support the functionality required to fulfill the request",
    )
    BAD_GATEWAY = (
        502,
        "Bad Gateway",
        "The server, while acting as a gateway or proxy, received an invalid response from the upstream server",
    )
    SERVICE_UNAVAILABLE = (
        503,
        "Service Unavailable",
        "The server is currently unavailable",
    )
    GATEWAY_TIMEOUT = (
        504,
        "Gateway Timeout",
        "The server, while acting as a gateway or proxy, did not receive a timely response from the upstream server",
    )
    HTTP_VERSION_NOT_SUPPORTED = (
        505,
        "HTTP Version Not Supported",
        "The server does not support the HTTP protocol version used in the request",
    )
    VARIANT_ALSO_NEGOTIATES = (
        506,
        "Variant Also Negotiates",
        "Transparent content negotiation for the request results in a circular reference",
    )
    INSUFFICIENT_STORAGE = (
        507,
        "Insufficient Storage",
        "The server is unable to store the representation needed to complete the request",
    )
    LOOP_DETECTED = (
        508,
        "Loop Detected",
        "The server detected an infinite loop while processing the request",
    )
    NOT_EXTENDED = (
        510,
        "Not Extended",
        "Further extensions to the request are required for the server to fulfill it",
    )
    NETWORK_AUTHENTICATION_REQUIRED = (
        511,
        "Network Authentication Required",
        "The client needs to authenticate to gain network access",
    )


class HTTPMethod(StrEnum):
    """HTTP methods and descriptions."""

    def __new__(cls, value: str, description: str):
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj.description = description
        return obj

    def __repr__(self) -> str:
        return f"<HTTPMethod.{str(self)}>"

    CONNECT = (
        "CONNECT",
        "Establishes a tunnel to the server identified by the target resource",
    )
    DELETE = "DELETE", "Deletes the specified resource"
    GET = "GET", "Requests a representation of the specified resource"
    HEAD = (
        "HEAD",
        "Asks for a response identical to a GET request, but without the response body",
    )
    OPTIONS = "OPTIONS", "Describes the communication options for the target resource"
    PATCH = "PATCH", "Applies partial modifications to a resource"
    POST = "POST", "Submits data to be processed to a specified resource"
    PUT = "PUT", "Uploads a representation of the specified resource"
    TRACE = (
        "TRACE",
        "Performs a message loop-back test along the path to the target resource",
    )
