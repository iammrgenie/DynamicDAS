cmake_minimum_required(VERSION 3.20.0)

set(BOARD nrf52840dk_nrf52840)
#set(BOARD sam_v71_xult)

find_package(Zephyr REQUIRED HINTS  $ENV{ZEPHYR_BASE})
project(my_app)


target_sources(app 
	PRIVATE 
		src/main.c
		c25519/src/c25519.c
		c25519/src/ed25519.c
		c25519/src/f25519.c
		c25519/src/sha256.c
		c25519/src/utils.c
		$ENV{ZEPHYR_BASE}/lib/libc/minimal/source/stdlib/rand.c
)
