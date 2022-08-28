#!/bin/bash
ASAN_OPTIONS=detect_leaks=0:coverage=1 /PX4-Autopilot/build/px4_sitl_default/bin/px4 -workers=4 -detect_leaks=0 /out
/bin/bash

