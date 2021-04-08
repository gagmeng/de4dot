/*
    Copyright (C) 2011-2015 de4dot@gmail.com

    This file is part of de4dot.

    de4dot is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    de4dot is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with de4dot.  If not, see <http://www.gnu.org/licenses/>.
*/

using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using de4dot.blocks;

namespace de4dot.code.deobfuscators.Dotfuscator {
	class StringDecrypter {
		ModuleDefMD module;
		MethodDefAndDeclaringTypeDict<StringDecrypterInfo> stringDecrypterMethods = new MethodDefAndDeclaringTypeDict<StringDecrypterInfo>();

		public class StringDecrypterInfo {
			public MethodDef method;
			public int magic;
			public StringDecrypterInfo(MethodDef method, int magic) {
				this.method = method;
				this.magic = magic;
			}
		}

		public bool Detected => stringDecrypterMethods.Count > 0;

		public IEnumerable<MethodDef> StringDecrypters {
			get {
				var list = new List<MethodDef>(stringDecrypterMethods.Count);
				foreach (var info in stringDecrypterMethods.GetValues())
					list.Add(info.method);
				return list;
			}
		}

		public IEnumerable<StringDecrypterInfo> StringDecrypterInfos => stringDecrypterMethods.GetValues();
		public StringDecrypter(ModuleDefMD module) => this.module = module;

		public void Find(ISimpleDeobfuscator simpleDeobfuscator) {
			foreach (var type in module.GetTypes())
				FindStringDecrypterMethods(type, simpleDeobfuscator);
		}

		void FindStringDecrypterMethods(TypeDef type, ISimpleDeobfuscator simpleDeobfuscator) {
			foreach (var method in DotNetUtils.FindMethods(type.Methods, "System.String", new string[] { "System.String", "System.Int32" })) {
				if (method.Body.HasExceptionHandlers)
					continue;

				if (DotNetUtils.GetMethodCalls(method, "System.Char[] System.String::ToCharArray()") != 1)
					continue;
				if (DotNetUtils.GetMethodCalls(method, "System.String System.String::Intern(System.String)") != 1)
					continue;

				simpleDeobfuscator.Deobfuscate(method);
				var instrs = method.Body.Instructions;
				for (int i = 0; i < instrs.Count - 6; i++) {
					var ldarg = instrs[i];
					if (!ldarg.IsLdarg() || ldarg.GetParameterIndex() != 0)
						continue;
					var callvirt = instrs[i + 1];
					if (callvirt.OpCode.Code != Code.Callvirt)
						continue;
					var calledMethod = callvirt.Operand as MemberRef;
					if (calledMethod == null || calledMethod.FullName != "System.Char[] System.String::ToCharArray()")
						continue;
					var stloc = instrs[i + 2];
					if (!stloc.IsStloc())
						continue;
					var ldci4 = instrs[i + 3];
					if (!ldci4.IsLdcI4())
						continue;
					var ldarg2 = instrs[i + 4];
					if (!ldarg2.IsLdarg() || ldarg2.GetParameterIndex() != 1)
						continue;
					var opAdd1 = instrs[i + 5];
					if (opAdd1.OpCode != OpCodes.Add)
						continue;

					int magicAdd = 0;
					int j = i + 6;
					/* 根据Dotfuscator("257420:1:0:4.39.0.8792", 0)特点修改-gagmeng */
					/* IL_0000: ldarg.0 */
					/* IL_0001: callvirt  instance char[] [mscorlib]System.String::ToCharArray() */
					/* IL_0006: stloc.0 */
					/* IL_0007: ldc.i4    951789305 */
					/* IL_000C: ldarg.1 */
					/* IL_000D: add */
					/* IL_000E: ldc.i4    63 */
					/* IL_0013: conv.i */
					/* IL_0014: add */
					/* IL_0015: ldc.i4    57 */
					/* IL_001A: conv.i */
					/* IL_001B: add */
					/* IL_001C: ldc.i4    68 */
					/* IL_0021: conv.i */
					/* IL_0022: add */
					/* IL_0023: ldc.i4    21 */
					/* IL_0028: conv.i */
					/* IL_0029: add */
					/* IL_002A: ldc.i4    85 */
					/* IL_002F: conv.i */
					/* IL_0030: add */
					/* IL_0031: stloc.1 */
					bool ldcflg = false;
					int ldcInstrsIdx = 0;
					Instruction ldcOp = Instruction.Create(OpCodes.Ldc_I4_0);
					Instruction addOp;
					while (j < instrs.Count - 1 && !instrs[j].IsStloc()) {
						if (ldcflg == false) 
						{
							ldcOp = instrs[j];
							if (ldcOp.IsLdcI4()) {
								ldcInstrsIdx = j;
								ldcflg = true;
							}
						}
						if (ldcflg == true) {
							addOp = instrs[j];
							if (addOp.OpCode == OpCodes.Add) {
								if(j <= ldcInstrsIdx + 2) {
									magicAdd = magicAdd + ldcOp.GetLdcI4Value();
									ldcflg = false;
								}
							}
						}
						j++;
					}

					var info = new StringDecrypterInfo(method, ldci4.GetLdcI4Value() + magicAdd);
					stringDecrypterMethods.Add(info.method, info);
					Logger.v("Found string decrypter method: {0}, magic: 0x{1:X8}", Utils.RemoveNewlines(info.method), info.magic);
					break;
				}
			}
		}

		public string Decrypt(IMethod method, string encrypted, int value) {
			var info = stringDecrypterMethods.FindAny(method);
			char[] chars = encrypted.ToCharArray();
			byte key = (byte)(info.magic + value);
			for (int i = 0; i < chars.Length; i++) {
				char c = chars[i];
				byte b1 = (byte)((byte)c ^ key++);
				byte b2 = (byte)((byte)(c >> 8) ^ key++);
				chars[i] = (char)((b1 << 8) | b2);
			}
			return new string(chars);
		}
	}
}
