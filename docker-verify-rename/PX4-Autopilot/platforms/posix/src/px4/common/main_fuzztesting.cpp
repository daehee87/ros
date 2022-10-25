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
#include "fuzz.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include "common/mavlink.h"

#define MODULE_NAME "px4"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

char fuzzing_buffer[4096];

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
	PX4_WARN("start mavlink now.");    
        pxh.process_line("mavlink start -x -o 14540 -r 4000000", true);
        pxh.process_line("mavlink boot_complete", true);
}

/*
 * enum Opcode : uint8_t {
	kCmdNone,		///< ignored, always acked
	kCmdTerminateSession,	///< Terminates open Read session
	kCmdResetSessions,	///< Terminates all open Read sessions
	kCmdListDirectory,	///< List files in <path> from <offset>
	kCmdOpenFileRO,		///< Opens file at <path> for reading, returns <session>
	kCmdReadFile,		///< Reads <size> bytes from <offset> in <session>
	kCmdCreateFile,		///< Creates file at <path> for writing, returns <session>
	kCmdWriteFile,		///< Writes <size> bytes to <offset> in <session>
	kCmdRemoveFile,		///< Remove file at <path>
	kCmdCreateDirectory,	///< Creates directory at <path>
	kCmdRemoveDirectory,	///< Removes Directory at <path>, must be empty
	kCmdOpenFileWO,		///< Opens file at <path> for writing, returns <session>
	kCmdTruncateFile,	///< Truncate file at <path> to <offset> length
	kCmdRename,		///< Rename <path1> to <path2>
	kCmdCalcFileCRC32,	///< Calculate CRC32 for file at <path>
	kCmdBurstReadFile,	///< Burst download session file

	kRspAck = 128,		///< Ack response
	kRspNak			///< Nak response
};
*/

struct __attribute__((__packed__)) PayloadHeader {
	uint16_t	seq_number;	///< sequence number for message
	uint8_t		session;	///< Session id for read and write commands
	uint8_t		opcode;		///< Command opcode
	uint8_t		size;		///< Size of data
	uint8_t		req_opcode;	///< Request opcode returned in kRspAck, kRspNak message
	uint8_t		burst_complete; ///< Only used if req_opcode=kCmdBurstReadFile - 1: set of burst packets complete, 0: More burst packets coming.
	uint8_t		padding;        ///< 32 bit aligment padding
	uint32_t	offset;		///< Offsets for List and Read commands
	uint8_t		data[];		///< command data, varies by Opcode
};

void send_mavlink(const uint8_t *data, const size_t size)
{
	mavlink_message_t message {};
	mavlink_file_transfer_protocol_t ftp {};

	int maxlen=239; // kMaxDataLength 

	for (size_t i = 0; i < size; i += sizeof(message)) {

		const size_t copy_len = std::min(sizeof(message), size - i);
		//printf("copy_len: %zu, %zu (%zu)\n", i, copy_len, size);
		memcpy(reinterpret_cast<void *>(&message), data + i, copy_len);

		message.magic = MAVLINK_STX_MAVLINK1;
		message.seq = 255;
		message.sysid = 255;
		message.compid = 255;
		message.msgid = MAVLINK_MSG_ID_FILE_TRANSFER_PROTOCOL;

		ftp.target_network = 0;
		ftp.target_system = 0;
		ftp.target_component = 0;
		PayloadHeader *payload = reinterpret_cast<PayloadHeader *>(&(ftp.payload[0]));
		payload->opcode = 13; //kCmdRename;	
		payload->seq_number++;
		payload->size = maxlen;
		memset(payload->data, 0x41, maxlen);	// fill entire data buffer as single string. will be null-terminated by PX4 side code
		memcpy(ftp.payload, payload, 251);
		
		// #define MAVLINK_MSG_ID_FILE_TRANSFER_PROTOCOL_LEN 254
		memcpy(message.payload64, &ftp, 254);

		// send packet.
		memcpy(fuzzing_buffer, &message, sizeof(message));		
	}
}


