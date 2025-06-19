package ghidra.app.util.bin.format.elf.relocation;

import java.util.Map;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.program.model.address.Address;

public class S1C33_ElfRelocationContext extends ElfRelocationContext<S1C33_ElfRelocationHandler> {

	protected S1C33_ElfRelocationContext(S1C33_ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, symbolMap);
		// TODO Auto-generated constructor stub
	}

}
