/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  * Additional permission under GNU GPL version 3 section 7
  *
  * If you modify this Program, or any covered work, by linking or combining
  * it with OpenSSL (or a modified version of that library), containing parts
  * covered by the terms of OpenSSL License and SSLeay License, the licensors
  * of this Program grant you additional permission to convey the resulting work.
  *
  */

#include <stdarg.h>
#include <assert.h>
#include <cstdlib>
#include <algorithm>
#include <chrono>

#include "jpsock.hpp"
#include "socks.hpp"
#include "socket.hpp"

#include "xmrstak/misc/executor.hpp"
#include "xmrstak/jconf.hpp"
#include "xmrstak/misc/jext.hpp"
#include "xmrstak/version.hpp"

using namespace rapidjson;

static constexpr int kNumParamsInGetWorkResponse = 4;

uint32_t random_4_bytes;

struct jpsock::call_rsp
{
	bool bHaveResponse;
	uint64_t iCallId;
	Value* pCallData;
	std::string sCallErr;
	uint64_t iMessageId;

	call_rsp(Value* val) : pCallData(val), iMessageId(0)
	{
		bHaveResponse = false;
		iCallId = 0;
		sCallErr.clear();
	}
};

typedef GenericDocument<UTF8<>, MemoryPoolAllocator<>, MemoryPoolAllocator<>> MemDocument;

/*
 *
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ASSUMPTION - only one calling thread. Multiple calling threads would require better
 * thread safety. The calling thread is assumed to be the executor thread.
 * If there is a reason to call the pool outside of the executor context, consider
 * doing it via an executor event.
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *
 * Call values and allocators are for the calling thread (executor). When processing
 * a call, the recv thread will make a copy of the call response and then erase its copy.
 */

struct jpsock::opaque_private
{
	Value  oCallValue;

	MemoryPoolAllocator<> callAllocator;
	MemoryPoolAllocator<> recvAllocator;
	MemoryPoolAllocator<> parseAllocator;
	MemDocument jsonDoc;
	call_rsp oCallRsp;

	opaque_private(uint8_t* bCallMem, uint8_t* bRecvMem, uint8_t* bParseMem) :
		callAllocator(bCallMem, jpsock::iJsonMemSize),
		recvAllocator(bRecvMem, jpsock::iJsonMemSize),
		parseAllocator(bParseMem, jpsock::iJsonMemSize),
		jsonDoc(&recvAllocator, jpsock::iJsonMemSize, &parseAllocator),
		oCallRsp(nullptr)
	{
	}
};

struct jpsock::opq_json_val
{
	const Value* val;
	opq_json_val(const Value* val) : val(val) {}
};

jpsock::jpsock(size_t id, const char* sAddr, const char* sLogin, const char* sRigId, const char* sPassword, double pool_weight, bool dev_pool, bool tls, const char* tls_fp, bool nicehash) :
	net_addr(sAddr), usr_login(sLogin), usr_rigid(sRigId), usr_pass(sPassword), tls_fp(tls_fp), pool_id(id), pool_weight(pool_weight), pool(dev_pool), nicehash(nicehash),
	connect_time(0), connect_attempts(0), disconnect_time(0), quiet_close(false)
{
	sock_init();

	bJsonCallMem = (uint8_t*)malloc(iJsonMemSize);
	bJsonRecvMem = (uint8_t*)malloc(iJsonMemSize);
	bJsonParseMem = (uint8_t*)malloc(iJsonMemSize);

	prv = new opaque_private(bJsonCallMem, bJsonRecvMem, bJsonParseMem);

#ifndef CONF_NO_TLS
	if(tls)
		sck = new tls_socket(this);
	else
		sck = new plain_socket(this);
#else
	sck = new plain_socket(this);
#endif

	oRecvThd = nullptr;
	bRunning = false;
	bLoggedIn = false;
	iJobDiff = 0;

	memset(&oCurrentJob, 0, sizeof(oCurrentJob));
}

jpsock::~jpsock()
{
	delete prv;
	prv = nullptr;

	free(bJsonCallMem);
	free(bJsonRecvMem);
	free(bJsonParseMem);
}

std::string&& jpsock::get_call_error()
{
	call_error = false;
	return std::move(prv->oCallRsp.sCallErr);
}

bool jpsock::set_socket_error(const char* a)
{
	if(!bHaveSocketError)
	{
		bHaveSocketError = true;
		sSocketError.assign(a);
	}

	return false;
}

bool jpsock::set_socket_error(const char* a, const char* b)
{
	if(!bHaveSocketError)
	{
		bHaveSocketError = true;
		size_t ln_a = strlen(a);
		size_t ln_b = strlen(b);

		sSocketError.reserve(ln_a + ln_b + 2);
		sSocketError.assign(a, ln_a);
		sSocketError.append(b, ln_b);
	}

	return false;
}

bool jpsock::set_socket_error(const char* a, size_t len)
{
	if(!bHaveSocketError)
	{
		bHaveSocketError = true;
		sSocketError.assign(a, len);
	}

	return false;
}

bool jpsock::set_socket_error_strerr(const char* a)
{
	char sSockErrText[512];
	return set_socket_error(a, sock_strerror(sSockErrText, sizeof(sSockErrText)));
}

bool jpsock::set_socket_error_strerr(const char* a, int res)
{
	char sSockErrText[512];
	return set_socket_error(a, sock_gai_strerror(res, sSockErrText, sizeof(sSockErrText)));
}

void jpsock::jpsock_thread()
{
	jpsock_thd_main();

	if(!bHaveSocketError)
		set_socket_error("Socket closed.");

	executor::inst()->push_event(ex_event(std::move(sSocketError), quiet_close, pool_id));

	std::unique_lock<std::mutex> mlock(call_mutex);
	bool bWait = prv->oCallRsp.pCallData != nullptr;

	// If a call is waiting, wait a little bit before blowing it out of the water
	if(bWait)
	{
		mlock.unlock();
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		mlock.lock();
	}

	// If the call is still there send an error to end it
	bool bCallWaiting = false;
	if(prv->oCallRsp.pCallData != nullptr)
	{
		prv->oCallRsp.bHaveResponse = true;
		prv->oCallRsp.iCallId = 0;
		prv->oCallRsp.pCallData = nullptr;
		prv->oCallRsp.iMessageId = 0;
		bCallWaiting = true;
	}
	mlock.unlock();

	if(bCallWaiting)
		call_cond.notify_one();

	bLoggedIn = false;

	if(bHaveSocketError && !quiet_close)
		disconnect_time = get_timestamp();
	else
		disconnect_time = 0;

	std::unique_lock<std::mutex> lck(job_mutex);
	memset(&oCurrentJob, 0, sizeof(oCurrentJob));
	bRunning = false;
}

bool jpsock::jpsock_thd_main()
{
	// Since a call to rand() doesn't usually give 32 bits of randomness
	// (31 bits is common but it depends on library version), we just
	// call rand() twice and take 2 least significant bytes from each
	// call. Initialization for rand(), i.e. srand(), was done already
	// in main(). The rand() call usually isn't thread safe, but rand()
	// gets called so rarely in xmr-stak that the chance of issues is
	// very low.
	unsigned int r1 = rand();
	unsigned int r2 = rand();
	random_4_bytes = (r2 << 16) | (0x0000ffff & r1);

	if(!sck->connect())
		return false;

	executor::inst()->push_event(ex_event(EV_SOCK_READY, pool_id));

	char buf[iSockBufferSize];
	size_t datalen = 0;
	while (true)
	{
		int ret = sck->recv(buf + datalen, sizeof(buf) - datalen);

		if(ret <= 0)
			return false;

		datalen += ret;

		if (datalen >= sizeof(buf))
		{
			sck->close(false);
			return set_socket_error("RECEIVE error: data overflow");
		}

		char* lnend;
		char* lnstart = buf;
		while ((lnend = (char*)memchr(lnstart, '\n', datalen)) != nullptr)
		{
			lnend++;
			int lnlen = lnend - lnstart;

			if (!process_line(lnstart, lnlen))
			{
				sck->close(false);
				return false;
			}

			datalen -= lnlen;
			lnstart = lnend;
		}

		//Got leftover data? Move it to the front
		if (datalen > 0 && buf != lnstart)
			memmove(buf, lnstart, datalen);
	}
}

bool jpsock::process_line(char* line, size_t len)
{
	prv->jsonDoc.SetNull();
	prv->parseAllocator.Clear();
	prv->callAllocator.Clear();
	++iMessageCnt;

	/*NULL terminate the line instead of '\n', parsing will add some more NULLs*/
	line[len-1] = '\0';

	// Uncomment this printf if you're debugging RPC interactions
	// between xmr-stak and a mining pool.
	//printf("RECV: %s\n", line);

	if (prv->jsonDoc.ParseInsitu(line).HasParseError())
		return set_socket_error("PARSE error: Invalid JSON");

	if (!prv->jsonDoc.IsObject())
		return set_socket_error("PARSE error: Invalid root");

	const Value* mt = nullptr;
	// We condition on bLoggedIn here because the original code was
	// structured in a way that treats the first 3-arg "result" (which
	// is just a job specified by block header and difficulty/target)
	// slightly differently than subsequent 3-arg "result" received from
	// the pool. The distinction isn't needed in the case of ethereum
	// stratum protocol but it's easier to just check bLoggedIn here and
	// let the original code mostly do the same as before.
	if (bLoggedIn && prv->jsonDoc.HasMember("result")) {
		mt = GetObjectMember(prv->jsonDoc, "result");
	}
	if (mt != nullptr && mt->IsArray() && mt->Size() == kNumParamsInGetWorkResponse) {
		opq_json_val v(mt);
		return process_pool_job(&v, iMessageCnt);
	}
	else
	{
		uint64_t iCallId;
		mt = GetObjectMember(prv->jsonDoc, "id");
		if (mt == nullptr)
			return set_socket_error("PARSE error: Protocol error 3");

		if (mt->IsUint64()) {
			iCallId = mt->GetUint64();
		} else if (mt->IsString()) {
			iCallId = atoi(mt->GetString());
		} else {
			return set_socket_error("PARSE error: couldn't figure out id");
		}

		mt = GetObjectMember(prv->jsonDoc, "error");

		const char* sError = nullptr;
		size_t iErrorLen = 0;
		if (mt == nullptr || mt->IsNull())
		{
			/* If there was no error we need a result */
			if ((mt = GetObjectMember(prv->jsonDoc, "result")) == nullptr)
				return set_socket_error("PARSE error: Protocol error 7");
		}
		else
		{
			if(!mt->IsObject())
				return set_socket_error("PARSE error: Protocol error 5");

			const Value* msg = GetObjectMember(*mt, "message");

			if(msg == nullptr || !msg->IsString())
				return set_socket_error("PARSE error: Protocol error 6");

			iErrorLen = msg->GetStringLength();
			sError = msg->GetString();
		}

		std::unique_lock<std::mutex> mlock(call_mutex);
		if (prv->oCallRsp.pCallData == nullptr)
		{
			/*Server sent us a call reply without us making a call*/
			mlock.unlock();
			return set_socket_error("PARSE error: Unexpected call response");
		}

		prv->oCallRsp.bHaveResponse = true;
		prv->oCallRsp.iCallId = iCallId;
		prv->oCallRsp.iMessageId = iMessageCnt;

		if(sError != nullptr)
		{
			prv->oCallRsp.pCallData = nullptr;
			prv->oCallRsp.sCallErr.assign(sError, iErrorLen);
			call_error = true;
		}
		else {
			prv->oCallRsp.pCallData->CopyFrom(*mt, prv->callAllocator);
		}

		mlock.unlock();
		call_cond.notify_one();

		return true;
	}
}

bool jpsock::process_pool_job(const opq_json_val* params, const uint64_t messageId)
{
	std::unique_lock<std::mutex> mlock(job_mutex);
	if(messageId < iLastMessageId)
	{
		/* In the case where the processed job message id is lesser than the last
		 * processed job message id we skip the processing to avoid mining old jobs
		 */
		printf("ignoring pool job with old message ID\n");
		return true;
	}
	iLastMessageId = messageId;

	mlock.unlock();


	// The full response should look something like this:
	// {"id":"1","jsonrpc":"2.0","result":["0x1c35a746c07bfbe88bd2babffa0a21e0a971fbd0e231a361ecaf6edf643540f6","0x0000000000000000000000000000000000000000000000000000000000000000","0x1f3526859b8cec01f3526859b8cec01f3526859b8cec01f3526859b8cec01f","334"]}
	// The 'params' arg should contain the contents of "result"
	const Value* result = params->val;
	if (result == nullptr || !result->IsArray() || result->Size() != kNumParamsInGetWorkResponse) {
		printf("eth_getWork response doesn't contain 'result' array or it's wrong size\n");
		return false;
	}

	std::string block_header_hex = (*result)[0].GetString();
	std::string target_hex = (*result)[2].GetString();
	std::string block_height_decimal_str = (*result)[3].GetString();
	unsigned long long block_height = strtoull(block_height_decimal_str.c_str(), nullptr, 10);
	if (block_height == 0) {
		printf("failed to parse block height: %s\n", block_height_decimal_str.c_str());
		return false;
	}

	// Trim "0x" prefix.
	block_header_hex = block_header_hex.substr(2, block_header_hex.size() - 2);
	target_hex = target_hex.substr(2, target_hex.size() - 2);
	// Uncomment this printf if you're debugging RPC interactions
	// between xmr-stak and a mining pool.
	//printf("header: %s\n", block_header_hex.c_str());
	//printf("target: %s\n", target_hex.c_str());
	int leading_zeros = 64 - target_hex.size();
	std::string tmp_hex;
	for (int i = 0; i < leading_zeros; i++) {
		tmp_hex.push_back('0');
	}
	int significant_digits = 16 - leading_zeros;
	for (int i = 0; i < significant_digits; i++) {
		tmp_hex.push_back(target_hex[i]);
	}
	// Reverse endianness so that hex2bin calls below will behave
	// correctly.
	target_hex.resize(tmp_hex.size());
	for (int i = 0; i < tmp_hex.size(); i += 2) {
		target_hex[i] = tmp_hex[tmp_hex.size() - i - 2];
		target_hex[i+1] = tmp_hex[tmp_hex.size() - i - 1];
	}

	/*
	   Check out these for more info on monero hash blob structure:
	   1. https://monero.stackexchange.com/questions/6459/monero-pool-job-contents-blob-length
	   2. https://monero.stackexchange.com/questions/6799/how-to-generate-a-blob-for-pow-hashing

	   I've pasted some of that info below. We'll use 8 as the major
	   version, which corresponds with cryptonight variant 2, and we'll
	   use zeros for minor version and timestamp since those fields don't
	   matter for us. We'll use ethereum's HashNoNonce in place of
	   prev_id, since HashNoNonce already has a bunch of stuff baked in
	   since it's derived from things like hash of transaction set for
	   this block and from parent's hash. Monero also inserts stuff after
	   the nonce such as tree root hash and transaction set size, but
	   again we don't need these since such things are already baked into
	   HashNoNonce in ethereum. In place of tree root hash etc, in order
	   to keep the blob byte length the same as for Monero (since this
	   miner code makes a lot of assumptions about the length of the
	   blob, specifically that it's 76 bytes), we'll just pad the rest of
	   the blob with byte value 119 (0x77). In the future, would probably
	   be better to re-copy the same bytes from HashNoNonce to pad the
	   blob size, but we're working in quick and dirty fashion right now
	   so we just use 119.

	   +---------------+------------------+--------------------------------+
	   |     Field     |       Type       |            Content             | Typical byte length
	   +---------------+------------------+--------------------------------+
	   | major_version | varint           | Major block header version     | 1
	   |               |                  |                                |
	   +---------------+------------------+--------------------------------+
	   | minor_version | varint           | Minor block header version     | 1
	   |               |                  |                                |
	   +---------------+------------------+--------------------------------+
	   | timestamp     | varint           | Block creation time            | 5
	   |               |                  | (UNIX timestamp)               |
	   +---------------+------------------+--------------------------------+
	   | prev_id       | hash             | Identifier of the previous     | 32
	   |               |                  | block                          |
	   +---------------+------------------+--------------------------------+
	   | nonce         | 4 bytes          | Any value which is used in the | 4
	   |               |                  | network consensus algorithm    |
	   +---------------+------------------+--------------------------------+
	 */

	char hexblob[153]; // 76 x 2 (byte to hex) and one extra byte for null termination
	for (int i = 0; i < 153; i++) {
		// Initialize everything with arbitrary choice of byte value 119 (0x77).
		hexblob[i] = '7';
	}
	hexblob[152] = '\0';
	int hexlen = 0;

	// major version (1 byte x2 hex)
	hexblob[hexlen++] = '0';
	hexblob[hexlen++] = 'a';  // This would need to be '7' for cryptonight variant 1 or '8' for variant 2. But we assume variant 4 which is byte value 10 so 'a' in hex.
	// minor version (1 byte x2 hex)
	hexblob[hexlen++] = '0';
	hexblob[hexlen++] = '0';
	// timestamp (5 byte x2 hex)
	for (int i = 0; i < 10; i++) {
		hexblob[hexlen++] = '0';
	}

	if (block_header_hex.size() == 64) {
		for (int i = 0; i < 64; i++) {
			hexblob[hexlen++] = block_header_hex[i];
		}
	} else {
		printf("block header is incorrect length: %lu\n", block_header_hex.size());
		return false;
	}

	// Set least significant 4 bytes of nonce to zero. The cpu and
	// gpu code later pull it out from this byte offset and
	// distribute+increment the nonce space over multiple threads.
	for (int i = 0; i < 8; i++) {  // 4 byte x2 hex
		hexblob[hexlen++] = '0';
	}
	// Set the most significant 4 bytes of nonce to random number,
	// to be different from others who are running xmr-stak. The
	// top 4 bytes will remain untouched by downstream code.
	char rand_buf[8];
	bin2hex((const unsigned char*)&random_4_bytes, 4, rand_buf);
	for (int i = 0; i < 8; i++) {
		hexblob[hexlen++] = rand_buf[i];
	}

	// By placing the 8 nonce bytes (16 hex bytes) according to
	// the above, the 8 consecutive nonce bytes can be considered
	// a little endian number.

	// 2 + 2 + 10 + 64 + 8 + 8
	if (hexlen != 94) {
		printf("something went wrong with constructing hexblob bytes; hexlen was %d instead of 94\n", hexlen);
		return false;
	}

	/*
	if (!params->val->IsObject())
		return set_socket_error("PARSE error: Job error 1");

	const Value *blob, *jobid, *target, *motd, *blk_height;
	jobid = GetObjectMember(*params->val, "job_id");
	blob = GetObjectMember(*params->val, "blob");
	target = GetObjectMember(*params->val, "target");
	motd = GetObjectMember(*params->val, "motd");
	blk_height = GetObjectMember(*params->val, "height");

	if (jobid == nullptr || blob == nullptr || target == nullptr ||
		!jobid->IsString() || !blob->IsString() || !target->IsString())
	{
		return set_socket_error("PARSE error: Job error 2");
	}

	if(motd != nullptr && motd->IsString() && (motd->GetStringLength() & 0x01) == 0)
	{
		std::unique_lock<std::mutex> lck(motd_mutex);
		if(motd->GetStringLength() > 0)
		{
			pool_motd.resize(motd->GetStringLength()/2 + 1);
			if(!hex2bin(motd->GetString(), motd->GetStringLength(), (unsigned char*)&pool_motd.front()))
				pool_motd.clear();
		}
		else
			pool_motd.clear();
	}

	if (jobid->GetStringLength() >= sizeof(pool_job::sJobID)) // Note >=
		return set_socket_error("PARSE error: Job error 3");
	 */

	pool_job oPoolJob;

	const uint32_t iWorkLen = 76;
	oPoolJob.iWorkLen = iWorkLen;

	if (iWorkLen > sizeof(pool_job::bWorkBlob))
		return set_socket_error("PARSE error: Invalid job length. Are you sure you are mining the correct coin?");

	if (!hex2bin(hexblob, iWorkLen * 2, oPoolJob.bWorkBlob))
		return set_socket_error("PARSE error: Job error 4");

	if (sizeof(pool_job::sJobID) != block_header_hex.size()) {
		printf("length of job id should match length of block header: %lu vs %lu\n", sizeof(pool_job::sJobID), block_header_hex.size());
		return false;
	}

	// lock reading of oCurrentJob
	std::unique_lock<std::mutex> jobIdLock(job_mutex);
	// compare possible non equal length job id's
	if(iWorkLen == oCurrentJob.iWorkLen && memcmp(oPoolJob.bWorkBlob, oCurrentJob.bWorkBlob, iWorkLen) == 0 &&
		memcmp(block_header_hex.c_str(), oCurrentJob.sJobID, block_header_hex.size()) == 0)
	{
		return set_socket_error("Duplicate equal job detected! Please contact your pool admin.");
	}
	jobIdLock.unlock();

	// Since we don't get sent a job id from the mining pool like in
	// monero case, we invent our own by hacking block header into job
	// id. For one we need to save the block header somewhere so we can
	// later submit it if we find a valid nonce. Second, it seems like
	// the code may rely on unique job id for certain things, so the
	// block header should work since it should indeed be unique.
	memset(oPoolJob.sJobID, 0, sizeof(pool_job::sJobID));
	memcpy(oPoolJob.sJobID, block_header_hex.c_str(), block_header_hex.size());

	size_t target_slen = target_hex.size();
	if(target_slen <= 8)
	{
		uint32_t iTempInt = 0;
		char sTempStr[] = "00000000"; // Little-endian CPU FTW
		memcpy(sTempStr, target_hex.c_str(), target_slen);
		if(!hex2bin(sTempStr, 8, (unsigned char*)&iTempInt) || iTempInt == 0)
			return set_socket_error("PARSE error: Invalid target");

		oPoolJob.iTarget = t32_to_t64(iTempInt);
	}
	else if(target_slen <= 16)
	{
		oPoolJob.iTarget = 0;
		char sTempStr[] = "0000000000000000";
		memcpy(sTempStr, target_hex.c_str(), target_slen);
		if(!hex2bin(sTempStr, 16, (unsigned char*)&oPoolJob.iTarget) || oPoolJob.iTarget == 0)
			return set_socket_error("PARSE error: Invalid target");
	}
	else
		return set_socket_error("PARSE error: Job error 5");

	iJobDiff = t64_to_diff(oPoolJob.iTarget);
	unsigned long long integer_difficulty = iJobDiff;
	printf("Pool set difficulty to %lld\n", integer_difficulty);
	
	oPoolJob.iBlockHeight = bswap_64(static_cast<uint64_t>(block_height));

	std::unique_lock<std::mutex> lck(job_mutex);
	oCurrentJob = oPoolJob;
	lck.unlock();
	// send event after current job data are updated
	executor::inst()->push_event(ex_event(oPoolJob, pool_id));

	return true;
}

bool jpsock::connect(std::string& sConnectError)
{
	ext_algo = ext_backend = ext_hashcount = ext_motd = false;
	bHaveSocketError = false;
	call_error = false;
	sSocketError.clear();
	iJobDiff = 0;
	connect_attempts++;
	connect_time = get_timestamp();

	if(sck->set_hostname(net_addr.c_str()))
	{
		bRunning = true;
		disconnect_time = 0;
		oRecvThd = new std::thread(&jpsock::jpsock_thread, this);
		return true;
	}

	disconnect_time = get_timestamp();
	sConnectError = std::move(sSocketError);
	return false;
}

void jpsock::disconnect(bool quiet)
{
	quiet_close = quiet;
	sck->close(false);

	if(oRecvThd != nullptr)
	{
		oRecvThd->join();
		delete oRecvThd;
		oRecvThd = nullptr;
	}

	sck->close(true);
	quiet_close = false;
}

bool jpsock::cmd_ret_wait(const char* sPacket, opq_json_val& poResult, uint64_t& messageId)
{
	// Uncomment this printf if you're debugging RPC interactions
	// between xmr-stak and a mining pool.
	//printf("SEND: %s\n", sPacket);

	/*Set up the call rsp for the call reply*/
	prv->oCallValue.SetNull();
	prv->callAllocator.Clear();

	std::unique_lock<std::mutex> mlock(call_mutex);
	prv->oCallRsp = call_rsp(&prv->oCallValue);
	mlock.unlock();

	if(!sck->send(sPacket))
	{
		disconnect(); //This will join the other thread;
		return false;
	}

	//Success is true if the server approves, result is true if there was no socket error
	bool bSuccess;
	mlock.lock();
	bool bResult = call_cond.wait_for(mlock, std::chrono::seconds(jconf::inst()->GetCallTimeout()),
		[&]() { return prv->oCallRsp.bHaveResponse; });

	bSuccess = prv->oCallRsp.pCallData != nullptr;
	prv->oCallRsp.pCallData = nullptr;
	mlock.unlock();

	if(bHaveSocketError)
		return false;

	//This means that there was no socket error, but the server is not taking to us
	if(!bResult)
	{
		set_socket_error("CALL error: Timeout while waiting for a reply");
		disconnect();
		return false;
	}

	if(bSuccess)
	{
		poResult.val = &prv->oCallValue;
		messageId = prv->oCallRsp.iMessageId;
	}
	return bSuccess;
}

bool jpsock::cmd_login()
{
	char cmd_buffer[1024];

	// The new line ("\n") is very important, as it causes the socket to actually flush the buffer when we tell it to send a message.
	snprintf(cmd_buffer, sizeof(cmd_buffer), "{\"method\": \"eth_submitLogin\", \"params\": [\"%s\"], \"id\": \"1\", \"jsonrpc\": \"2.0\"}\n",
			usr_login.c_str());

	opq_json_val oResult(nullptr);
	uint64_t messageId = 0;

	/*Normal error conditions (failed login etc..) will end here*/
	if (!cmd_ret_wait(cmd_buffer, oResult, messageId)) {
		return false;
	}

	// Successful login response looks like this:
	//   { "id": 1, "jsonrpc": "2.0", "result": true }
	// Unsuccessful looks like this:
	//   { "id": 1, "jsonrpc": "2.0", "result": null, "error": { code: -1, message: "Invalid login" } }

	//printf("type: %d\n", oResult.val->GetType());
	if (!oResult.val->IsTrue())
	{
		printf("login result was false, one possible reason is that login info might be invalid\n");
		set_socket_error("PARSE error: Login protocol error 1");
		disconnect();
		return false;
	} else {
		printf("logged in!\n");
	}

	char getwork_cmd_buffer[1024];
	snprintf(getwork_cmd_buffer, sizeof(getwork_cmd_buffer), "{\"method\": \"eth_getWork\", \"id\": \"1\", \"jsonrpc\": \"2.0\"}\n");

	opq_json_val getworkResult(nullptr);
	uint64_t getworkMessageId = 0;

	if (!cmd_ret_wait(getwork_cmd_buffer, getworkResult, getworkMessageId)) {
		printf("eth_getWork failed\n");
		return false;
	}

	/*
	const Value* id = GetObjectMember(*oResult.val, "id");
	const Value* job = GetObjectMember(*oResult.val, "job");
	const Value* ext = GetObjectMember(*oResult.val, "extensions");

	if (id == nullptr || job == nullptr || !id->IsString())
	{
		set_socket_error("PARSE error: Login protocol error 2");
		disconnect();
		return false;
	}

	if (id->GetStringLength() >= sizeof(sMinerId))
	{
		set_socket_error("PARSE error: Login protocol error 3");
		disconnect();
		return false;
	}

	memset(sMinerId, 0, sizeof(sMinerId));
	memcpy(sMinerId, id->GetString(), id->GetStringLength());

	if(ext != nullptr && ext->IsArray())
	{
		for(size_t i=0; i < ext->Size(); i++)
		{
			const Value& jextname = ext->GetArray()[i];

			if(!jextname.IsString())
				continue;

			std::string tmp(jextname.GetString());
			std::transform(tmp.begin(), tmp.end(), tmp.begin(), ::tolower);

			if(tmp == "algo")
				ext_algo = true;
			else if(tmp == "backend")
				ext_backend = true;
			else if(tmp == "hashcount")
				ext_hashcount = true;
			else if(tmp == "motd")
				ext_motd = true;
		}
	}
	 */

	if (!process_pool_job(&getworkResult, messageId))
	{
		disconnect();
		return false;
	}

	bLoggedIn = true;
	connect_attempts = 0;

	return true;
}

bool jpsock::cmd_submit(const char* sJobId, uint32_t iNonce, uint32_t iNonceUpper, const uint8_t* bResult, const char* backend_name, uint64_t backend_hashcount, uint64_t total_hashcount, const xmrstak_algo& algo)
{
	char cmd_buffer[1024];
	char sNonce[17];
	char sResult[65];
	char strJobId[65];

	/*Extensions*/
	/*
	char sAlgo[64] = {0};
	char sBaseAlgo[64] = {0};
	char sIterations[32] = {0};
	char sMemory[32] = {0};
	char sMemAlignBytes[32] = {0};
	char sBackend[64] = {0};
	char sHashcount[128] = {0};

	if(ext_backend)
		snprintf(sBackend, sizeof(sBackend), ",\"backend\":\"%s\"", backend_name);

	if(ext_hashcount)
		snprintf(sHashcount, sizeof(sHashcount), ",\"hashcount\":%llu,\"hashcount_total\":%llu", int_port(backend_hashcount), int_port(total_hashcount));

	if(ext_algo)
	{
		snprintf(sAlgo, sizeof(sAlgo), ",\"algo\":\"%s\"", algo.Name().c_str());
		// the real algorithm with three degrees of freedom
		snprintf(sBaseAlgo, sizeof(sBaseAlgo), ",\"base_algo\":\"%s\"", algo.BaseName().c_str());
		snprintf(sIterations, sizeof(sIterations), ",\"iterations\":\"0x%08x\"", algo.Iter());
		snprintf(sMemory, sizeof(sMemory), ",\"scratchpad\":\"0x%08x\"", (uint32_t)algo.Mem());
		snprintf(sMemAlignBytes, sizeof(sMemAlignBytes), ",\"mask\":\"0x%08x\"", algo.Mask());
	}
	 */

	uint64_t iNonce64 = static_cast<uint64_t>(iNonce);
	uint64_t iNonceUpper64 = static_cast<uint64_t>(iNonceUpper);
	uint64_t fullNonce = (iNonceUpper64 << 32) | iNonce64;
	// Change nonce from any endian (probably little) to big endian.
	unsigned char nbuf[8];
	nbuf[7] = fullNonce & 0xff;
	nbuf[6] = (fullNonce >> 8) & 0xff;
	nbuf[5] = (fullNonce >> 16) & 0xff;
	nbuf[4] = (fullNonce >> 24) & 0xff;
	nbuf[3] = (fullNonce >> 32) & 0xff;
	nbuf[2] = (fullNonce >> 40) & 0xff;
	nbuf[1] = (fullNonce >> 48) & 0xff;
	nbuf[0] = (fullNonce >> 56) & 0xff;
	bin2hex(nbuf, 8, sNonce);
	sNonce[16] = '\0';

	memcpy(strJobId, sJobId, 64);
	strJobId[64] = '\0';

	bin2hex(bResult, 32, sResult);
	sResult[64] = '\0';

	snprintf(cmd_buffer, sizeof(cmd_buffer), "{\"method\": \"eth_submitWork\", \"params\": [\"0x%s\", \"0x%s\", \"0x%s\"], \"worker\": \"%s\", \"id\":1}\n",
			sNonce, strJobId/*block_header*/, sResult, usr_rigid.c_str());

	uint64_t messageId = 0;
	opq_json_val oResult(nullptr);
	if (!cmd_ret_wait(cmd_buffer, oResult, messageId)) {
		return false;
	}
	// Possible responses:
	//   {"id":1,"jsonrpc":"2.0","result":false}
	//   {"id":1,"jsonrpc":"2.0","result":true}
	const Value* result = oResult.val;
	if (result == nullptr || !result->IsBool()) {
		printf("eth_submitWork response doesn't contain 'result' or isn't bool\n");
		return false;
	}

	return result->IsTrue();
}

void jpsock::save_nonce(uint32_t nonce)
{
	std::unique_lock<std::mutex> lck(job_mutex);
	oCurrentJob.iSavedNonce = nonce;
}

bool jpsock::get_current_job(pool_job& job)
{
	std::unique_lock<std::mutex> lck(job_mutex);

	if(oCurrentJob.iWorkLen == 0)
		return false;

	job = oCurrentJob;
	return true;
}

bool jpsock::get_pool_motd(std::string& strin)
{
	if(!ext_motd)
		return false;

	std::unique_lock<std::mutex> lck(motd_mutex);
	if(pool_motd.size() > 0)
	{
		strin.assign(pool_motd);
		return true;
	}

	return false;
}

inline unsigned char hf_hex2bin(char c, bool &err)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 0xA;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 0xA;

	err = true;
	return 0;
}

bool jpsock::hex2bin(const char* in, unsigned int len, unsigned char* out)
{
	bool error = false;
	for (unsigned int i = 0; i < len; i += 2)
	{
		out[i / 2] = (hf_hex2bin(in[i], error) << 4) | hf_hex2bin(in[i + 1], error);
		if (error) return false;
	}
	return true;
}

inline char hf_bin2hex(unsigned char c)
{
	if (c <= 0x9)
		return '0' + c;
	else
		return 'a' - 0xA + c;
}

void jpsock::bin2hex(const unsigned char* in, unsigned int len, char* out)
{
	for (unsigned int i = 0; i < len; i++)
	{
		out[i * 2] = hf_bin2hex((in[i] & 0xF0) >> 4);
		out[i * 2 + 1] = hf_bin2hex(in[i] & 0x0F);
	}
}
