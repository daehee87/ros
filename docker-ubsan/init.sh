#!/bin/bash
python3 /4dfuzzer_file.py /out &
/PX4-Autopilot/build/px4_sitl_default/bin/px4 -workers=4 /out
/bin/bash

