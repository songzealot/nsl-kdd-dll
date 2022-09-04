#include "ForStart.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <string.h>
#include <new>          // std::bad_alloc
#include <csignal>
#include <cstdlib>
#include <assert.h>

#include "Config.h"
#include "Sniffer.h"
#include "IpReassembler.h"
#include "ConversationReconstructor.h"
#include "StatsEngine.h"

using namespace std;
using namespace FeatureExtractor;

static volatile bool temination_requested = false;

void signal_handler(int signum);
//void usage(const char* name);
//int list_interfaces();
//void parse_args(int argc, char** argv, Config* config);
//void invalid_option(const char* opt, const char* progname);
//void invalid_option_value(const char* opt, const char* val, const char* progname);
void extract(Sniffer* sniffer, const Config* config, bool is_running_live);

//테스트용
//Test()에서 받은 string 값 저장
string output;
//값 전달 확인
bool output_check = false;
//output_check 상태 리턴
bool output_status();
//output_check 다시 false로 돌림
void output_false();
//~~~~~~
//인터페이스 인덱스 찾기
int interfaces_num(const char* dev_name);


void Test(char* dev_name) {
	// Register signal handler for termination
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
#ifdef SIGBREAK
	signal(SIGBREAK, signal_handler);
#endif

	int interface_num;
	int interface_cnt;
	string name;

	//통합 준비 작업
	//interface_num, result_type 수정 필요
	/*
	for (;;) {
		cout << "인터페이스 선택" << endl;
		interface_cnt = list_interfaces();
		cin >> interface_num;
		if (!(interface_num > 0 && interface_num < interface_cnt)||cin.fail()) {
			cout << "잘못된 입력" << endl;
			cin.clear();
			cin.ignore(INT_MAX, '\n');
			continue;
		}
		break;
	}

	for (;;) {
		int rt1;
		cout << "결과 출력 방식" << endl;
		cout << "1. 콘솔에만 출력" << endl;
		cout << "2. 파일로도 출력" << endl;
		cin >> rt1;
		if (!(rt1 == 1 || rt1 == 2)||cin.fail()) {
			cout << "잘못된 입력" << endl;
			cin.clear();
			cin.ignore(INT_MAX, '\n');
			continue;
		}
		else if (rt1 == 1) {
			result_type = 1;
		}
		else if (rt1 == 2) {
			cout << "출력될 파일 이름 입력" << endl;
			cin >> name;
			for (;;) {
				int rt2;
				cout << "파일 이어쓰기" << endl;
				cout << "1. 이어쓰기" << endl;
				cout << "2. 덮어쓰기" << endl;
				cin.ignore();
				cin >> rt2;
				if (!(rt2 == 1 || rt2 == 2)||cin.fail()) {
					cout << "잘못된 입력" << endl;
					cin.clear();
					cin.ignore(INT_MAX, '\n');
					continue;
				}
				result_type = rt1 * 10 + rt2;
				break;
			}
		}
		break;
	}
	*/

	try {
		Config config;

		interface_num = interfaces_num(dev_name);

		config.set_interface_num(interface_num);
		//cout << "1단계" << endl;

		if (config.get_files_count() == 0) {
			// Input from interface
			//cout << "2단계" << endl;
			int inum = config.get_interface_num();
			if (config.should_print_filename())
				cout << "INTERFACE " << inum << endl;
			Sniffer* sniffer = new Sniffer(inum, &config);
			extract(sniffer, &config, true);
			cout << "으악" << endl;
		}
		else {
			// Input from files
			/*
			int count = config.get_files_count();
			char** files = config.get_files_values();
			for (int i = 0; i < count; i++) {
				if (config.should_print_filename())
					cout << "FILE '" << files[i] << "'" << endl;

				Sniffer* sniffer = new Sniffer(files[i], &config);
				extract(sniffer, &config, false);
			}
			*/
		}
	}
	catch (std::bad_alloc& ba)	// Inform when memory limit reached
	{
		std::cerr << "Error allocating memory (Exception bad_alloc): " << ba.what() << '\n';
		return;
	}
}

void signal_handler(int signum)
{
	cerr << "Terminating extractor (signal " << signum << " received)" << endl;
	temination_requested = true;
}

/*
//void -> int
int list_interfaces()
{

	pcap_if_t* alldevs;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;

	// Retrieve the device list
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		cerr << "Error in pcap_findalldevs: " << errbuf << endl;
		exit(1);
	}

	// Print the list
	for (d = alldevs, i = 1; d; d = d->next, i++) {

		cout << i << ". "
			<< setiosflags(ios_base::left) << setw(40) << (char*)((d->description != 0) ? d->description : "NULL")
			<< "\t[" << d->name << ']' << endl;
	}
	cout << endl;

	// Free the device list
	pcap_freealldevs(alldevs);

	return i;
}
*/

// 인터페이스 인덱스 찾기
int interfaces_num(const char * dev_name)
{

	pcap_if_t* alldevs;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;

	// Retrieve the device list
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		cerr << "Error in pcap_findalldevs: " << errbuf << endl;
		exit(1);
	}

	// 디바이스 이름 -> 인터페이스 인덱스
	for (d = alldevs, i = 1; d; d = d->next, i++) {
		if (dev_name == d->name) {
			return i;
		}
	}

	// Free the device list
	pcap_freealldevs(alldevs);
	pcap_freealldevs(d);
}

void extract(Sniffer* sniffer, const Config* config, bool is_running_live)
{
	IpReassembler reasm;
	ConversationReconstructor conv_reconstructor;
	StatsEngine stats_engine(config);

	bool has_more_traffic = true;
	int cnt = 0;

	while (!temination_requested && (has_more_traffic || is_running_live)) {

		// Get frame from sniffer
		IpFragment* frag = sniffer->next_frame();
		has_more_traffic = (frag != NULL);


		Packet* datagr = nullptr;
		if (has_more_traffic) {
			// Do some assertion about the type of packet just to be sure
			// If sniffer's filter fails to fulfill this assertion, "continue" can be used here
			eth_field_type_t eth_type = frag->get_eth_type();
			ip_field_protocol_t ip_proto = frag->get_ip_proto();
			assert((eth_type == IPV4 && (ip_proto == TCP || ip_proto == UDP || ip_proto == ICMP))
				&& "Sniffer returned packet that is not (TCP or UDP or ICMP)");

			Timestamp now = frag->get_end_ts();

			// IP Reassembly, frag must not be used after this
			datagr = reasm.reassemble(frag);

			// Conversation reconstruction
			if (datagr) {
				conv_reconstructor.add_packet(datagr);
			}
			else {
				// Tell conversation reconstruction just how the time goes on
				conv_reconstructor.report_time(now);
			}
		}

		// Output timedout conversations 
		Conversation* conv;

		while ((conv = conv_reconstructor.get_next_conversation()) != nullptr) {
			cnt++;
			ConversationFeatures* cf = stats_engine.calculate_features(conv);
			conv = nullptr;		// Should not be used anymore, object will commit suicide

			//cout << "3-1단계 " << cnt << endl;
			//cf->print(config->should_print_extra_features());
			string print_output = cf->print(config->should_print_extra_features());
			output = print_output;
			output_check = true;
			delete cf;
		}
	}

	// If no more traffic, finish everything
	conv_reconstructor.finish_all_conversations();

	// Output leftover conversations
	Conversation* conv;
	while ((conv = conv_reconstructor.get_next_conversation()) != nullptr) {
		cnt++;
		ConversationFeatures* cf = stats_engine.calculate_features(conv);
		conv = nullptr;

		//cout << "3-2단계" << endl;
		//cf->print(config->should_print_extra_features());
		string print_output = cf->print(config->should_print_extra_features());
		output = print_output;
		output_check = true;
		delete cf;
	}
	cout << cnt <<"개의 데이터 생성됨" << endl;
}

//output 관련 함수

bool output_status() {
	return output_check;
}
void output_false() {
	output_check = false;
}

//output return
const char* rt_output() {
	const char* output_c = output.c_str();
	return output_c;
}