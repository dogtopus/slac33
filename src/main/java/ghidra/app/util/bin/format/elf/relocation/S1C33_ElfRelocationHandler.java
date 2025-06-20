package ghidra.app.util.bin.format.elf.relocation;

import java.util.Map;
import java.util.NoSuchElementException;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.symbol.Symbol;

public class S1C33_ElfRelocationHandler extends AbstractElfRelocationHandler<S1C33_ElfRelocationType, S1C33_ElfRelocationContext> {
	private static final String DP_BASE_SYM = "__dp";
	private static final String GDP_BASE_SYM = "__gdp";
	private static final String SDP_BASE_SYM = "__sdp";
	private static final String TDP_BASE_SYM = "__tdp";
	private static final String ZDP_BASE_SYM = "__zdp";

	public S1C33_ElfRelocationHandler() {
		super(S1C33_ElfRelocationType.class);
	}

	@Override
	protected S1C33_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return new S1C33_ElfRelocationContext(this, loadHelper, symbolMap);
	}

	@Override
	protected RelocationResult relocate(S1C33_ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			S1C33_ElfRelocationType relocationType, Address relocationAddress, ElfSymbol elfSymbol, Address symbolAddr,
			long symbolValue, String symbolName) throws MemoryAccessException {
		Program program = elfRelocationContext.getProgram();
		Memory mem = program.getMemory();

		final MessageLog log = elfRelocationContext.getLog();

		switch (relocationType) {
		case R_C33_NONE:
			return RelocationResult.SKIPPED;
		case R_C33_PUSHN_R0:
			mem.setShort(relocationAddress, (short) 0x0200);
			return new RelocationResult(Status.APPLIED, 2);
		case R_C33_PUSHN_R1:
			mem.setShort(relocationAddress, (short) 0x0201);
			return new RelocationResult(Status.APPLIED, 2);
		case R_C33_32:
			mem.setInt(relocationAddress, (int) (symbolValue & 0xffffffffl));
			return new RelocationResult(Status.APPLIED, 4);
		case R_C33_16:
			mem.setShort(relocationAddress, (short) (symbolValue & 0xffffl));
			return new RelocationResult(Status.APPLIED, 2);
		case R_C33_8:
			mem.setByte(relocationAddress, (byte) (symbolValue & 0xffl));
			return new RelocationResult(Status.APPLIED, 1);
		case R_C33_AH:
			patchExtImm13(mem, relocationAddress, (short) (symbolValue >> 13));
			return new RelocationResult(Status.APPLIED, 2);
		case R_C33_AL:
			patchExtImm13(mem, relocationAddress, (short) symbolValue);
			return new RelocationResult(Status.APPLIED, 2);
		case R_C33_H: {
			patchExtImm13(mem, relocationAddress, (short) (symbolValue >> 19));
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_M: {
			patchExtImm13(mem, relocationAddress, (short) (symbolValue >> 6));
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_L: {
			patchImm6(mem, relocationAddress, (short) symbolValue);
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_DH: {
			Long dpRel = calculateXDPRel(program, DP_BASE_SYM, symbolValue);
			if (dpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, (short) (dpRel >> 13));
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_DL: {
			Long dpRel = calculateXDPRel(program, DP_BASE_SYM, symbolValue);
			if (dpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, dpRel.shortValue());
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_GL: {
			Long gdpRel = calculateXDPRel(program, GDP_BASE_SYM, symbolValue);
			if (gdpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, gdpRel.shortValue());
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_SH: {
			Long sdpRel = calculateXDPRel(program, SDP_BASE_SYM, symbolValue);
			if (sdpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, (short) (sdpRel >> 13));
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_SL: {
			Long sdpRel = calculateXDPRel(program, SDP_BASE_SYM, symbolValue);
			if (sdpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, sdpRel.shortValue());
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_TH: {
			Long tdpRel = calculateXDPRel(program, TDP_BASE_SYM, symbolValue);
			if (tdpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, (short) (tdpRel >> 13));
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_TL: {
			Long tdpRel = calculateXDPRel(program, TDP_BASE_SYM, symbolValue);
			if (tdpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, tdpRel.shortValue());
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_ZH: {
			Long zdpRel = calculateXDPRel(program, ZDP_BASE_SYM, symbolValue);
			if (zdpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, (short) (zdpRel >> 13));
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_ZL: {
			Long zdpRel = calculateXDPRel(program, ZDP_BASE_SYM, symbolValue);
			if (zdpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, zdpRel.shortValue());
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_DPH: {
			Long dpRel = calculateXDPRel(program, DP_BASE_SYM, symbolValue);
			if (dpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, (short) (dpRel >> 19));
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_DPM: {
			Long dpRel = calculateXDPRel(program, DP_BASE_SYM, symbolValue);
			if (dpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, (short) (dpRel >> 6));
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_DPL: {
			Long dpRel = calculateXDPRel(program, DP_BASE_SYM, symbolValue);
			if (dpRel == null) {
				return RelocationResult.FAILURE;
			}
			patchImm6(mem, relocationAddress, dpRel.shortValue());
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_RH:
		case R_C33_S_RH: {
			Long pcrel = calculatePCRel(relocationAddress, relocationType, symbolValue, symbolName, log);
			if (pcrel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, (short) ((pcrel >> 22) & 0x3ff));
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_RM:
		case R_C33_S_RM: {
			Long pcrel = calculatePCRel(relocationAddress, relocationType, symbolValue, symbolName, log);
			if (pcrel == null) {
				return RelocationResult.FAILURE;
			}
			patchExtImm13(mem, relocationAddress, (short) ((pcrel >> 9) & 0x1fff));
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_JP:
		case R_C33_RL:
		case R_C33_S_RL: {
			Long pcrel = calculatePCRel(relocationAddress, relocationType, symbolValue, symbolName, log);
			if (pcrel == null) {
				return RelocationResult.FAILURE;
			}
			patchSign8(mem, relocationAddress, (short) (pcrel >> 1));
			return new RelocationResult(Status.APPLIED, 2);
		}
		default:
			return RelocationResult.UNSUPPORTED;
		}
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_SE_C33;
	}
	
	/**
	 * Change an `ext` instruction's imm13 value to the one specified.
	 * @param mem Memory accessor.
	 * @param addr Address of the original instruction.
	 * @param imm13 Immediate value. Will apply a 13-bit mask before using.
	 * @throws MemoryAccessException
	 */
	private static void patchExtImm13(Memory mem, Address addr, short imm13) throws MemoryAccessException {
		short original = mem.getShort(addr);
		short patched = (short) ((original & 0xe000) | (imm13 & 0x1fff));
		mem.setShort(addr, patched);
	}

	/**
	 * Change an instruction's sign8 value to the one specified.
	 * @param mem Memory accessor.
	 * @param addr Address of the original instruction.
	 * @param sign8 Immediate value. Will apply an 8-bit mask before using.
	 * @throws MemoryAccessException
	 */
	private static void patchSign8(Memory mem, Address addr, short sign8) throws MemoryAccessException {
		short original = mem.getShort(addr);
		short patched = (short) ((original & 0xff00) | (sign8 & 0xff));
		mem.setShort(addr, patched);
	}

	/**
	 * Change an instruction's imm6 value to the one specified.
	 * @param mem Memory accessor.
	 * @param addr Address of the original instruction.
	 * @param imm6 Immediate value. Will apply an 6-bit mask before using.
	 * @throws MemoryAccessException
	 */
	private static void patchImm6(Memory mem, Address addr, short imm6) throws MemoryAccessException {
		short original = mem.getShort(addr);
		short patched = (short) ((original & 0xff00) | (imm6 & 0x3f));
		mem.setShort(addr, patched);
	}

	private static Long calculateXDPRel(Program program, String base, long symbolValue) {
		Symbol baseSym = null;
		try {
			baseSym = program.getSymbolTable().getGlobalSymbols(base).getFirst();
		} catch (NoSuchElementException e) {

		}
		if (baseSym == null) {
			return null;
		}
		long dBase = baseSym.getAddress().getOffset();
		return symbolValue - dBase;
	}

	private static Long calculatePCRel(
			Address relocationAddress,
			S1C33_ElfRelocationType relocationType,
			long symbolValue,
			String symbolName,
			MessageLog log
	) {
		if ((symbolValue & 1) != 0) {
			log.appendMsg(String.format("Symbol %s has invalid address %08x.", symbolName, symbolValue));
			return null;
		}
		long offset;
		if (relocationType == S1C33_ElfRelocationType.R_C33_S_RH || relocationType == S1C33_ElfRelocationType.R_C33_RH) {
			offset = 4;
		} else if (relocationType == S1C33_ElfRelocationType.R_C33_S_RM || relocationType == S1C33_ElfRelocationType.R_C33_RM) {
			offset = 2;
		} else {
			offset = 0;
		}
		Address presumedInstOffset = relocationAddress.add(offset);
		long pcrel = symbolValue - presumedInstOffset.getOffset();
		return pcrel;
	}
}
