// Package abyss_core provides the core networking module for the Abyss Browser.
// This builds a DLL library, and not expected to be used as an imported package.
//
// See https://github.com/kadmila/Abyss-Browser
//
// # Build Profiles
//
// The project supports two build profiles: debug and release.
// Using `-tags=debug` (as in build_dll_debug.ps1) enables the debug profile.
//
// # Directory Structure
//
// native_dll
//
//	Contains DLL exports for abyssnet.dll. The file `dllmain.go` defines
//	export symbols, and `marshalling.go` provides dynamic-length byte array
//	marshalling utilities.
//
// aerr
//
//	Defines all custom error types used across the project.
//
// ahmp
//
//	Contains AHMP message definitions. Serialization is not included.
//	For protocol details, see the AHMP specification.
//
// and
//
//	Implements the Abyss world neighbor discovery protocol.
//
// aurl
//
//	AbyssURL(AURL) handling and parsing utilities.
//
// crash
//
//	TODO: crash dump utility.
//
// host
//
//	main QUIC host
//
// interfaces
//
//	Interfaces hiding low-level network protocol implementations. This is designed for compatibility between different communication protocol/abyss neighbor discovery protocol implementations.
//
// net_service
//
//	low level networking service (implements `interfaces`).
//
// test
//
//	test suits
//
// test_logs
//
//	Stores .log files for test results. This directory should not be
//	committed to the repository.
//
// tools
//
//	utilities and helpers.
//
// watchdog
//
//	debug watchdog.
//
// See individual types and functions for more detailed documentation.
package abyss_core
