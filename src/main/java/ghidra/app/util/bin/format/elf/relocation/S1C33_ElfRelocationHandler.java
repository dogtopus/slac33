package ghidra.app.util.bin.format.elf.relocation;

import java.util.Map;

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

public class S1C33_ElfRelocationHandler extends AbstractElfRelocationHandler<S1C33_ElfRelocationType, S1C33_ElfRelocationContext> {

	public S1C33_ElfRelocationHandler() {
		super(S1C33_ElfRelocationType.class);
	}

	@Override
	protected S1C33_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		// TODO Auto-generated method stub
		return new S1C33_ElfRelocationContext(this, loadHelper, symbolMap);
	}

	@Override
	protected RelocationResult relocate(S1C33_ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			S1C33_ElfRelocationType relocationType, Address relocationAddress, ElfSymbol elfSymbol, Address symbolAddr,
			long symbolValue, String symbolName) throws MemoryAccessException {
		Program program = elfRelocationContext.getProgram();
		Memory mem = program.getMemory();

		// final MessageLog log = elfRelocationContext.getLog();

		switch (relocationType) {
		case R_C33_NONE:
			return RelocationResult.SKIPPED;
		case R_C33_DH: {
			long dpRel = calculateDPRel(symbolValue);
			short original = mem.getShort(relocationAddress);
			short patched = (short) ((original & 0xe000) | ((dpRel >> 13) & 0x1fff));
			mem.setShort(relocationAddress, patched);
			return new RelocationResult(Status.APPLIED, 2);
		}
		case R_C33_DL: {
			long dpRel = calculateDPRel(symbolValue);
			short original = mem.getShort(relocationAddress);
			short patched = (short) ((original & 0xe000) | (dpRel & 0x1fff));
			mem.setShort(relocationAddress, patched);
			return new RelocationResult(Status.APPLIED, 2);
		}
		default:
			return RelocationResult.FAILURE;
		}
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_SE_C33;
	}

	private static long calculateDPRel(long symbolValue) {
		return symbolValue;
	}
}
