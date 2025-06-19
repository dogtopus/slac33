package ghidra.app.util.bin.format.elf.extend;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.program.model.lang.Language;

public class S1C33_ElfExtension extends ElfExtension {

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_SE_C33;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language lang = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
				"S1C33".equals(lang.getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_S1C33";
	}

}
