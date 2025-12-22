package and

const (
	JNC_REDUNDANT = 110

	//Joiner-side problem
	JNC_NOT_FOUND = 404
	JNC_DUPLICATE = 480
	JNC_OVERRUN   = 481
	JNC_CANCELED  = 498
	JNC_CLOSED    = 499

	//Accepter-side response
	JNC_COLLISION      = 520
	JNC_INVALID_STATES = 521
	JNC_EXPIRED        = 530
	JNC_RESET          = 598
	JNC_REJECTED       = 599

	//Network issue
	JNC_DISCONNECTED = 600
)

const (
	JNM_REDUNDANT = "Already Joined"

	JNM_NOT_FOUND = "Not Found"
	JNM_DUPLICATE = "Duplicate Join"
	JNM_OVERRUN   = "World Session Overrun"
	JNM_CANCELED  = "Join Canceled"
	JNM_CLOSED    = "Peer Disconnected"

	JNM_COLLISION      = "Session ID Collided"
	JNM_INVALID_STATES = "Invalid States"
	JNM_EXPIRED        = "Join Expired"
	JNM_RESET          = "Reset Requested"
	JNM_REJECTED       = "Join Rejected"

	JNM_DISCONNECTED = "Disconnected"
)
