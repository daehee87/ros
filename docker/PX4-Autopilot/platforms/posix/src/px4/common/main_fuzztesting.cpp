/****************************************************************************
 *
 *   Copyright (C) 2022 PX4 Development Team. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name PX4 nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/**
 * This is an alternative main entrypoint for fuzz testing.
 */

#include <stdint.h>

#include "px4_platform_common/init.h"
#include "px4_platform_common/posix.h"
#include "apps.h"
#include "px4_daemon/client.h"
#include "px4_daemon/server.h"
#include "px4_daemon/pxh.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include "common/mavlink.h"

#define MODULE_NAME "px4"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif


namespace px4
{
void init_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, const size_t size);
void initialize_fake_px4_once();
void send_mavlink(const uint8_t *data, const size_t size);


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, const size_t size)
{
	initialize_fake_px4_once();

	send_mavlink(data, size);

	return 0;
}

void initialize_fake_px4_once()
{
	static bool first_time = true;

	if (!first_time) {
		return;
	}

	first_time = false;

	px4::init_once();
	px4::init(0, nullptr, "px4");

	px4_daemon::Pxh pxh;
	pxh.process_line("uorb start", true);
	pxh.process_line("param load", true);
	pxh.process_line("dataman start", true);
	pxh.process_line("load_mon start", true);
	pxh.process_line("battery_simulator start", true);
	pxh.process_line("tone_alarm start", true);
	pxh.process_line("rc_update start", true);
	pxh.process_line("sensors start", true);
	pxh.process_line("commander start", true);
	pxh.process_line("navigator start", true);
	pxh.process_line("ekf2 start", true);
	pxh.process_line("mc_att_control start", true);
	pxh.process_line("mc_pos_control start", true);
	pxh.process_line("land_detector start multicopter", true);
	pxh.process_line("logger start", true);
	
    pxh.process_line("controllib_test start", true);
    pxh.process_line("rc_tests start", true);
    pxh.process_line("uorb_tests start", true);
    pxh.process_line("wqueue_test start", true);
    pxh.process_line("camera_trigger start", true);
    pxh.process_line("gps start", true);
    pxh.process_line("pwm_out_sim start", true);
    pxh.process_line("rpm_simulator start", true);
    //pxh.process_line("tone_alarm start", true);
    pxh.process_line("airship_att_control start", true);
    pxh.process_line("airspeed_selector start", true);
    pxh.process_line("attitude_estimator_q start", true);
    pxh.process_line("camera_feedback start", true);
    //pxh.process_line("commander start", true);
    pxh.process_line("commander_tests start", true);
    pxh.process_line("control_allocator start", true);
    //pxh.process_line("dataman start", true);
    //pxh.process_line("ekf2 start", true);
    pxh.process_line("send_event start", true);
    pxh.process_line("flight_mode_manager start", true);
    pxh.process_line("fw_att_control start", true);
    pxh.process_line("fw_autotune_attitude_control start", true);
    pxh.process_line("fw_pos_control_l1 start", true);
    pxh.process_line("gimbal start", true);
    pxh.process_line("gyro_calibration start", true);
    pxh.process_line("gyro_fft start", true);
    //pxh.process_line("land_detector start", true);
    pxh.process_line("landing_target_estimator start", true);
    //pxh.process_line("load_mon start", true);
    pxh.process_line("local_position_estimator start", true);
    //pxh.process_line("logger start", true);
    pxh.process_line("mag_bias_estimator start", true);
    pxh.process_line("manual_control start", true);
    pxh.process_line("mavlink start", true);
    pxh.process_line("mavlink_tests start", true);
    //pxh.process_line("mc_att_control start", true);
    pxh.process_line("mc_autotune_attitude_control start", true);
    pxh.process_line("mc_hover_thrust_estimator start", true);
    //pxh.process_line("mc_pos_control start", true);
    pxh.process_line("mc_rate_control start", true);
    //pxh.process_line("navigator start", true);
    //pxh.process_line("rc_update start", true);
    pxh.process_line("replay start", true);
    pxh.process_line("rover_pos_control start", true);
    //pxh.process_line("sensors start", true);
    pxh.process_line("simulator start", true);
    //pxh.process_line("battery_simulator start", true);
    pxh.process_line("sensor_baro_sim start", true);
    pxh.process_line("sensor_gps_sim start", true);
    pxh.process_line("sensor_mag_sim start", true);
    pxh.process_line("temperature_compensation start", true);
    pxh.process_line("uuv_att_control start", true);
    pxh.process_line("uuv_pos_control start", true);
    pxh.process_line("vtol_att_control start", true);
    pxh.process_line("actuator_test start", true);
    pxh.process_line("dyn start", true);
    pxh.process_line("failure start", true);
    pxh.process_line("led_control start", true);
    pxh.process_line("mixer start", true);
    pxh.process_line("motor_test start", true);
    pxh.process_line("param start", true);
    pxh.process_line("perf start", true);
    pxh.process_line("pwm start", true);
    pxh.process_line("sd_bench start", true);
    pxh.process_line("shutdown start", true);
    pxh.process_line("system_time start", true);
    pxh.process_line("tests start", true);
    pxh.process_line("hrt_test start", true);
    pxh.process_line("listener start", true);
    pxh.process_line("tune_control start", true);
    pxh.process_line("uorb start", true);
    pxh.process_line("ver start", true);
    pxh.process_line("work_queue start", true);
    pxh.process_line("fake_gps start", true);
    pxh.process_line("fake_imu start", true);
    pxh.process_line("fake_magnetometer start", true);
    pxh.process_line("ex_fixedwing_control start", true);
    pxh.process_line("hello start", true);
    pxh.process_line("px4_mavlink_debug start", true);
    pxh.process_line("px4_simple_app start", true);
    pxh.process_line("rover_steering_control start", true);
    pxh.process_line("uuv_example_app start", true);
    pxh.process_line("work_item_example start", true);
    pxh.process_line("list_tasks start", true);
    pxh.process_line("list_files start", true);
        
    pxh.process_line("mavlink start -x -o 14540 -r 4000000", true);
	pxh.process_line("mavlink boot_complete", true);
}

void send_mavlink(const uint8_t *data, const size_t size)
{
	int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (socket_fd < 0) {
		PX4_ERR("socket error: %s", strerror(errno));
		return;
	}

	struct sockaddr_in addr {};

	addr.sin_family = AF_INET;

	inet_pton(AF_INET, "0.0.0.0", &(addr.sin_addr));

	addr.sin_port = htons(14540);

	if (bind(socket_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
		PX4_ERR("bind error: %s", strerror(errno));
		close(socket_fd);
		return;
	}

	mavlink_message_t message {};
	uint8_t buffer[MAVLINK_MAX_PACKET_LEN] {};

	for (size_t i = 0; i < size; i += sizeof(message)) {

		const size_t copy_len = std::min(sizeof(message), size - i);
		//printf("copy_len: %zu, %zu (%zu)\n", i, copy_len, size);
		memcpy(reinterpret_cast<void *>(&message), data + i, copy_len);

		const ssize_t buffer_len = mavlink_msg_to_send_buffer(buffer, &message);

		struct sockaddr_in dest_addr {};
		dest_addr.sin_family = AF_INET;

		inet_pton(AF_INET, "127.0.0.1", &dest_addr.sin_addr.s_addr);
		dest_addr.sin_port = htons(14556);

		if (sendto(socket_fd, buffer, buffer_len, 0, reinterpret_cast<sockaddr *>(&dest_addr),
			   sizeof(dest_addr)) != buffer_len) {
			PX4_ERR("sendto error: %s", strerror(errno));
		}
	}


	close(socket_fd);
}


