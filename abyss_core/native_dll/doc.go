// DLL export definitions
//
// # Return Code
//
// All DLL export functions with C.int return indicates the following.
//
// EOF = -1
// : indicates end of data.
//
// ERROR = -1
// : indicates internal error.
//
// INVALID_ARGUMENTS = -2
// : indicate caller fault.
//
// BUFFER_OVERFLOW = -3
// : indicates OOM or internal memory limit reached.
//
// REMOTE_ERROR = -4
// : indicates a failure of other peers.
//
// INVALID_HANDLE = -99
// : indicates invalid handle reference of the caller.
package main
