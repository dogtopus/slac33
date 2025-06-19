package ghidra.app.util.bin.format.elf.relocation;

/**
 * S1C33 relocation constants copied from GNU33.
 */
public enum S1C33_ElfRelocationType implements ElfRelocationType {
	/** No-op. */
	R_C33_NONE(0),
	/** Patch a 32-bit value. */
	R_C33_32(1),
	/** Patch a 16-bit value. */
	R_C33_16(2),
	/** Patch a 8-bit value. */
	R_C33_8(3),
	R_C33_AH(4),
	R_C33_AL(5),
	R_C33_RH(6),
	R_C33_RM(7),
	R_C33_RL(8),
	R_C33_H(9),
	R_C33_M(10),
	R_C33_L(11),
	/** Immediate DP-relative offset - high 13 bit (imm26 ...) */
	R_C33_DH(12),
	/** Immediate DP-relative offset - low 13 bit (imm13) */
	R_C33_DL(13),
	R_C33_GL(14),
	R_C33_SH(15),
	R_C33_SL(16),
	R_C33_TH(17),
	R_C33_TL(18),
	R_C33_ZH(19),
	R_C33_ZL(20),
	R_C33_DPH(21),
	R_C33_DPM(22),
	R_C33_DPL(23),
	R_C33_LOOP(24),
	R_C33_JP(25),
	/** Immediate PC-relative offset - high 10 bit (pcrel32 ...) */
	R_C33_S_RH(26),
	/** Immediate PC-relative offset - mid 13 bit (pcrel22 ...) */
	R_C33_S_RM(27),
	/** Immediate PC-relative offset - low 9 bit (LSB always 0) (pcrel9) */
	R_C33_S_RL(28),
	R_C33_PUSHN_R0(29),
	R_C33_PUSHN_R1(30),
	R_C33_PUSH_R1(31);

	public final int typeId;

	private S1C33_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return this.typeId;
	}
}
