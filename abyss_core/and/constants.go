package and

// TODO : revise this

const (
	JNC_REDUNDANT = 110

	//Joiner-side problem
	JNC_NOT_FOUND = 404
	JNC_DUPLICATE = 480
	JNC_OVERRUN   = 481
	JNC_CANCELED  = 498
	JNC_CLOSED    = 499

	//Accepter-side response
	JNC_COLLISION = 520
	JNC_EXPIRED   = 530
	JNC_REJECTED  = 599

	//Non-Joining state
	JNC_UNEXPECTED_WSID = 600
	JNC_INVALID_STATES  = 610

	//Network issue
	JNC_DISCONNECTED = 700
)

const (
	JNM_REDUNDANT = "Already Joined"

	JNM_NOT_FOUND = "Not Found"
	JNM_DUPLICATE = "Duplicate Join"
	JNM_OVERRUN   = "World Session Overrun"
	JNM_CANCELED  = "Join Canceled"
	JNM_CLOSED    = "Peer Disconnected"

	JNM_COLLISION = "Session ID Collided"
	JNM_EXPIRED   = "Join Expired"
	JNM_REJECTED  = "Join Rejected"

	JNM_UNEXPECTED_WSID = "Unexpected Session ID"
	JNM_INVALID_STATES  = "Invalid States"

	JNM_DISCONNECTED = "Disconnected"
)
