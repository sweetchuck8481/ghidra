// This script converts the scalar operands in the selected section to UTF-16 characters
// and inserts a pre comment with the resulting string.
//@author tackleberry
//@category Stack
//@keybinding 
//@menupath 
//@toolbar 

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalLong;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.disassemble.*;

public class ReadUTF16StackStrings extends GhidraScript {

	@Override
	public void run() throws Exception {
		Address minAddr = currentSelection.getMinAddress();
		Address maxAddr = currentSelection.getMaxAddress();
		Address currentAddr = minAddr;
		StringBuilder sb = new StringBuilder();
		//Instruction ins = currentProgram.getListing().getInstructionAt(minAddr);
		
		for (Instruction ins : currentProgram.getListing().getInstructions(minAddr, true)) {
			currentAddr = ins.getAddress();
			//print(currentAddr.toString());
			if (currentAddr.compareTo(maxAddr) >= 0) {
				break;
			}
			byte[] barray = ins.getScalar(1).byteArrayValue();
//			for (byte b : barray) {
//				print(Integer.toHexString(b));
//			}
			//print("\n");
			String scalarAsString = new String(barray, "UTF-16");
			print(scalarAsString);
			sb.append(new StringBuilder(scalarAsString).reverse().toString().replaceAll("[\\p{C}]", ""));
			//print(sb.toString());
			//print("\n");
		}
		print("\n");
		print(sb.toString());
		print("\n");
		
		Listing listing = currentProgram.getListing();
        CodeUnit codeUnit = listing.getCodeUnitAt( minAddr );
        codeUnit.setComment( CodeUnit.PRE_COMMENT, "Stack string: " + sb.toString().strip() );
	}
}
