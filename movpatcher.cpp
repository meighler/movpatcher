#include <iostream>
#include <vector>
#include <cstring>
#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>

constexpr uint32_t MOV_X0_ZERO = 0xD2800000;

int main(int argc, char** argv){
	if (argc != 3){
		std::cerr << "Usage: " << argv[0] << " <restored_external> <restored_external_patched>\n";
		std::exit(1);
	}

	LIEF::logging::set_level(LIEF::logging::LEVEL::INFO);

	const std::unique_ptr<LIEF::MachO::FatBinary>  fat_macho = LIEF::MachO::Parser::parse(argv[1]);
	const std::unique_ptr<LIEF::MachO::Binary> arm64_slice = fat_macho->take(0);
	const LIEF::MachO::Section* cstring_section = arm64_slice->get_section("__cstring");
	const LIEF::MachO::Section* text_section = arm64_slice->get_section("__text");
	const std::string target_str = "ReferenceFramesInfo setCount: %d\n";
	const auto& cstring_data = cstring_section->content();
	std::vector<uint8_t> text_data(text_section->content().begin(), text_section->content().end());
	const uint64_t text_va = text_section->virtual_address();

	csh handle;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) return 1;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	cs_insn* insn;
	const size_t instr_count = cs_disasm(handle, text_data.data(), text_data.size(), text_va, 0, &insn);
	if (instr_count == 0){
		std::cerr << "Disassembly failed. You have no arms left. Sob. The Logs:\n" << cs_strerror(cs_errno(handle)) << "\n";
		cs_free(insn, instr_count);
		cs_close(&handle);
		std::exit(1);
	}
	std::cout << "Disassembled " << std::dec << instr_count << " instructions\n";

	const size_t str_offset = std::search(cstring_data.begin(), cstring_data.end(), target_str.begin(), target_str.end()) - cstring_data.begin();
	const uint64_t string_addr = cstring_section->virtual_address() + str_offset;
	std::cout << std::hex << "Found ReferenceFramesInfo setCount at: " << std::showbase << std::uppercase << std::hex << string_addr << "\n";

	bool patched = false;

	for (size_t i = 0; i < instr_count && !patched; i++){
		const auto& instr = insn[i];
        	if (instr.id == ARM64_INS_ADR && instr.detail->arm64.op_count >= 2 && instr.detail->arm64.operands[1].type == ARM64_OP_IMM){
			uint64_t xref_addr = instr.detail->arm64.operands[1].imm;    
			if (xref_addr == string_addr){
				std::cout << "Found ReferenceFramesInfo setCount xref at " << std::showbase << std::uppercase << std::hex << instr.address << "\n";

				size_t j = i;
				while (j < instr_count && insn[j].id != ARM64_INS_RET) j++;
		                for (ssize_t k = static_cast<ssize_t>(j) - 1; k >= 0; k--){
					const auto& prev_instr = insn[k];
					if (prev_instr.id == ARM64_INS_MOV && prev_instr.detail->arm64.op_count == 2 && prev_instr.detail->arm64.operands[0].type == ARM64_OP_REG && prev_instr.detail->arm64.operands[1].type == ARM64_OP_REG && prev_instr.detail->arm64.operands[0].reg == ARM64_REG_X0){
						const size_t mov_offset = prev_instr.address - text_va;
						if (mov_offset + 4 <= text_data.size()){
							std::memcpy(&text_data[mov_offset], &MOV_X0_ZERO, 4);
							std::cout << "Patched mov x0, " << cs_reg_name(handle, prev_instr.detail->arm64.operands[1].reg) << " to mov x0, #0 at " << std::showbase << std::uppercase << std::hex << prev_instr.address << "\n";
							patched = true;
							break;
						}
					}
				}
			}
		}
	}

	cs_free(insn, instr_count);
	cs_close(&handle);

	if (patched){
		try{
			const_cast<LIEF::MachO::Section*>(text_section)->content(text_data); // update content of the __text section in arm64_slice
			LIEF::MachO::Builder::config_t builder_config;
			builder_config.linkedit = false;
			arm64_slice->write(argv[2], builder_config);
			std::cout << "Patched restored_external written to " << argv[2] << "\n";
		}catch (const std::exception& e){
			std::cerr << "Failed to write patched binary: " << e.what() << "\n";
			std::exit(1);
		}
	}else{
		std::cerr << "Failed to patch restored_external.\n";
		std::exit(1);
	}
}
