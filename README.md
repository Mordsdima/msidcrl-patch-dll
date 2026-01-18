# some stuff for patching gfwl for custom servers

what it does?:
	- by using older msidcrl it bypasses required encryption stuff for RST2
	- hooks sendto calls to redirect to ur KDC
	- hooks connect calls to redirect to ur SSO server

changes except stuff defined above:
	- Updated to VS2026 instead of 2022

that's all :P, changes by Mordsdima, original code (GFLL) by InvoxiPlayGames, original readme can be found [here](./README.orig.md)

this code is pure hell btw so good luck reading this stuff