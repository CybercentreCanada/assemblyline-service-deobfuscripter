""" DeobfuScripter: Script Deobfuscation Service """

from __future__ import annotations

import binascii
import os

from collections import Counter
from typing import Callable, Dict, List, Optional, Tuple

import regex

from bs4 import BeautifulSoup
from multidecoder.query import squash_replace, obfuscation_counts

from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.extractor.decode_wrapper import DecoderWrapper, get_tree_tags
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest, MaxExtractedExceeded
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic


# Type declarations
TechniqueList = List[Tuple[str, Callable[[bytes], Optional[bytes]]]]


class DeobfuScripter(ServiceBase):
    """ Service for deobfuscating scripts """
    VALIDCHARS = b' 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
    BINCHARS = bytes(list(set(range(0, 256)) - set(VALIDCHARS)))

    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)

    def start(self) -> None:
        self.log.debug("DeobfuScripter service started")

    # --- Support Modules ----------------------------------------------------------------------------------------------

    def printable_ratio(self, text: bytes) -> float:
        """ Calcuate the ratio of printable characters to total characters in text """
        return float(float(len(text.translate(None, self.BINCHARS))) / float(len(text)))

    @staticmethod
    def add1b(s: bytes, k: int) -> bytes:
        """ Add k to each byte of s """
        return bytes([(c + k) & 0xff for c in s])

    def charcode(self, text: bytes) -> Optional[bytes]:
        """ Replace character codes with the corresponding characters """
        arrayofints = list(filter(lambda n: n < 256,
                                  map(int, regex.findall(r'(\d+)', str(regex.findall(rb'\D{1,2}\d{2,3}', text))))))
        if len(arrayofints) > 20:
            output = bytes(arrayofints)
            if self.printable_ratio(output) > .75 and (float(len(output)) / float(len(text))) > .10:
                # if the output is mostly readable and big enough
                return output

        return None

    @staticmethod
    def charcode_hex(text: bytes) -> Optional[bytes]:
        """ Replace hex character codes with the corresponding characters """
        output = text
        enc_str = [b'\\u', b'%u', b'\\x', b'0x']

        for encoding in enc_str:
            char_len = [(16, regex.compile(rb'(?:' + regex.escape(encoding) + b'[A-Fa-f0-9]{16}){2,}')),
                        (8, regex.compile(rb'(?:' + regex.escape(encoding) + b'[A-Fa-f0-9]{8}){2,}')),
                        (4, regex.compile(rb'(?:' + regex.escape(encoding) + b'[A-Fa-f0-9]{4}){2,}')),
                        (2, regex.compile(rb'(?:' + regex.escape(encoding) + b'[A-Fa-f0-9]{2}){2,}'))]

            for r in char_len:
                hexchars = set(regex.findall(r[1], text))

                for hex_char in hexchars:
                    data = hex_char
                    decoded = b''
                    if r[0] == 2:
                        while data != b'':
                            decoded += binascii.a2b_hex(data[2:4])
                            data = data[4:]
                    if r[0] == 4:
                        while data != b'':
                            decoded += binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[6:]
                    if r[0] == 8:
                        while data != b'':
                            decoded += binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                                binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[10:]
                    if r[0] == 16:
                        while data != b'':
                            decoded += binascii.a2b_hex(data[16:18]) + binascii.a2b_hex(data[14:16]) + \
                                binascii.a2b_hex(data[12:14]) + binascii.a2b_hex(data[10:12]) + \
                                binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                                binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[18:]

                    # Remove trailing NULL bytes
                    final_dec = regex.sub(b'[\x00]*$', b'', decoded)
                    output = output.replace(hex_char, final_dec)

        if output == text:
            return None
        return output

    @staticmethod
    def xml_unescape(text: bytes) -> Optional[bytes]:
        """ Replace XML escape sequences with the corresponding character """
        output = text
        for hex in regex.findall(rb'(?i)&#x[a-z0-9]{2};', text):
            output = output.replace(hex, binascii.unhexlify(hex[3:-1]))
        for escape in regex.findall(rb'&#(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2});', text):
            output = output.replace(escape, int(escape[2:-1]).to_bytes(1, 'big'))
        return output if output != text else None

    @staticmethod
    def vars_of_fake_arrays(text: bytes) -> Optional[bytes]:
        """ Parse variables of fake arrays """
        replacements = regex.findall(rb'var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\[(\d+)\]', text)
        if len(replacements) > 0:
            #    ,- Make sure we do not process these again
            output = regex.sub(rb'var\s+([^=]+)\s*=', rb'XXX \1 =', text)
            for varname, array, pos in replacements:
                try:
                    value = regex.split(rb'\s*,\s*', array)[int(pos)]
                except IndexError:
                    # print '[' + array + '][' + pos + ']'
                    break
                output = output.replace(varname, value)
            if output != text:
                return output
        return None

    def array_of_strings(self, text: bytes) -> Optional[bytes]:
        """ Replace arrays of strings with the combined string """
        # noinspection PyBroadException
        try:
            replacements = regex.findall(rb'var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\s*;', text)
            if len(replacements) > 0:
                #    ,- Make sure we do not process these again
                output = text
                for varname, values in replacements:
                    occurences = [int(x) for x in regex.findall(varname + rb'\s*\[(\d+)\]', output)]
                    for i in occurences:
                        try:
                            output = regex.sub(varname + rb'\s*\[(%d)\]' % i,
                                               values.split(b',')[i].replace(b'\\', b'\\\\'), output)
                        except IndexError:
                            # print '[' + array + '][' + pos + ']'
                            break
                if output != text:
                    return output
        except Exception as e:
            self.log.warning(f"Technique array_of_strings failed with error: {str(e)}")

        return None

    @staticmethod
    def powershell_vars(text: bytes) -> Optional[bytes]:
        """ Replace PowerShell variables with their values """
        replacements_string = regex.findall(rb'(\$(?:\w+|{[^\}]+\}))\s*=[^=]\s*[\"\']([^\"\']+)[\"\']', text)
        replacements_func = regex.findall(rb'(\$(?:\w+|{[^\}]+\}))\s*=\s*([^=\"\'\s$]{3,50})[\s]', text)
        if len(replacements_string) > 0 or len(replacements_func) > 0:
            #    ,- Make sure we do not process these again
            output = regex.sub(rb'\$((?:\w+|{[^\}]+\}))\s*=', rb'\$--\1 =', text)
            for varname, string in replacements_string:
                output = output.replace(varname, string)
            for varname, string in replacements_func:
                output = output.replace(varname, string)
            if output != text:
                return output

        return None

    @staticmethod
    def powershell_carets(text: bytes) -> Optional[bytes]:
        """ Remove PowerShell carets """
        try:
            if b"^" in text or b"`" in text:
                output = text
                for full in regex.findall(rb'"[^"]+[A-Za-z0-9](\^|`)+[A-Za-z0-9][^"]+"', text):
                    if isinstance(full, tuple):
                        full = full[0]
                    char_to_be_removed = b"^" if b"^" in full else b"`"
                    output = output.replace(full, full.replace(char_to_be_removed, b""))
                if output == text:
                    return None
                return output
        except TimeoutError:
            pass
        return None

    # noinspection PyBroadException
    def msoffice_embedded_script_string(self, text: bytes) -> Optional[bytes]:
        """ Replace variables with their values in MSOffice embedded scripts """
        try:
            scripts: Dict[bytes, List[bytes]] = {}
            output = text
            # bad, prevent false var replacements like YG="86"
            # Replace regular variables
            replacements = regex.findall(
                rb'^(\s*(\w+)\s*=\s*\w*\s*\+?\s(["\'])(.+)["\']\s*\+\s*vbCrLf\s*$)', output, regex.M)
            if len(replacements) > 0:
                for full, variable_name, delim, value in replacements:
                    scripts.setdefault(variable_name, [])
                    scripts[variable_name].append(value.replace(delim + delim, delim))
                    output = output.replace(full, b'<deobsfuscripter:msoffice_embedded_script_string_var_assignment>')

            for script_var, script_lines in scripts.items():
                new_script_name = b'new_script__' + script_var
                output = regex.sub(rb'(.+)\b' + script_var + rb'\b', b'\\1' + new_script_name, output)
                output += b"\n\n\n' ---- script referenced by \"" + new_script_name + b"\" ----\n\n\n"
                output += b"\n".join(script_lines)

            if output == text:
                return None
            return output

        except Exception as e:
            self.log.warning(f"Technique msoffice_embedded_script_string failed with error: {str(e)}")
            return None

    def mswordmacro_vars(self, text: bytes) -> Optional[bytes]:
        """ Replaces Microsoft Word variables with their values """
        # noinspection PyBroadException
        try:
            output = text
            # prevent false var replacements like YG="86"
            # Replace regular variables
            replacements = regex.findall(rb'^\s*((?:Const[\s]*)?(\w+)\s*='
                                         rb'\s*((?:["][^"]+["]|[\'][^\']+[\']|[0-9]*)))[\s\r]*$',
                                         output, regex.MULTILINE | regex.DOTALL)
            if len(replacements) > 0:
                # If one variable is defined more then once take the second definition
                replacements = [(v[0], k, v[1]) for k, v in {i[1]: (i[0], i[2]) for i in replacements}.items()]
                for full, varname, value in replacements:
                    if len(regex.findall(rb'\b' + varname + rb'\b', output)) == 1:
                        # If there is only one instance of these, it's probably noise.
                        output = output.replace(full, b'<deobsfuscripter:mswordmacro_unused_variable_assignment>')
                    else:
                        final_val = value.replace(b'"', b"")
                        # Stacked strings
                        # b = "he"
                        # b = b & "llo "
                        # b = b & "world!"
                        stacked = regex.findall(rb'^\s*(' + varname + rb'\s*=\s*'
                                                + varname + rb'\s*[+&]\s*((?:["][^"]+["]|[\'][^\']+[\'])))[\s\r]*$',
                                                output, regex.MULTILINE | regex.DOTALL)
                        if len(stacked) > 0:
                            for sfull, val in stacked:
                                final_val += val.replace(b'"', b"")
                                output = output.replace(sfull, b'<deobsfuscripter:mswordmacro_var_assignment>')
                        output = output.replace(full, b'<deobsfuscripter:mswordmacro_var_assignment>')
                        # If more than a of the variable name left, the assumption is that this did not
                        # work according to plan, so just replace a few for now.
                        output = regex.sub(rb'(\b' + regex.escape(varname) +
                                           rb'(?!\s*(?:=|[+&]\s*' + regex.escape(varname) + rb'))\b)',
                                           b'"' + final_val.replace(b"\\", b"\\\\") + b'"',
                                           output, count=5)
                        # output = regex.sub(rb'(.*[^\s].*)\b' + varname + rb'\b',
                        #                 b'\\1"' + final_val.replace(b"\\", b"\\\\") + b'"',
                        #                 output)

            # Remaining stacked strings
            replacements = regex.findall(rb'^\s*((\w+)\s*=\s*(\w+)\s*[+&]\s*((?:["][^"]+["]|[\'][^\']+[\'])))[\s\r]*$',
                                         output, regex.MULTILINE | regex.DOTALL)
            replacements_vars = {x[1] for x in replacements}
            for v in replacements_vars:
                final_val = b""
                for full, varname, _, value in replacements:
                    if varname != v:
                        continue
                    final_val += value.replace(b'"', b"")
                    output = output.replace(full, b'<deobsfuscripter:mswordmacro_var_assignment>')
                output = regex.sub(rb'(\b' + v +
                                   rb'(?!\s*(?:=|[+&]\s*' + v + rb'))\b)',
                                   b'"' + final_val.replace(b"\\", b"\\\\") + b'"',
                                   output, count=5)

            if output == text:
                return None
            return output

        except Exception as e:
            self.log.warning(f"Technique mswordmacro_vars failed with error: {str(e)}")
            return None

    def simple_xor_function(self, text: bytes) -> Optional[bytes]:
        """ Tries XORing the text with potential keys found in the text """
        xorstrings = regex.findall(rb'(\w+\("((?:[0-9A-Fa-f][0-9A-Fa-f])+)"\s*,\s*"([^"]+)"\))', text)
        option_a: List[Tuple[bytes, bytes, bytes, Optional[bytes]]] = []
        option_b: List[Tuple[bytes, bytes, bytes, Optional[bytes]]] = []
        output = text
        for f, x, k in xorstrings:
            res = self.xor_with_key(binascii.a2b_hex(x), k)
            if self.printable_ratio(res) == 1:
                option_a.append((f, x, k, res))
                # print 'A:',f,x,k, res
            else:
                option_a.append((f, x, k, None))
            # try by shifting the key by 1
            res = self.xor_with_key(binascii.a2b_hex(x), k[1:] + k[0:1])
            if self.printable_ratio(res) == 1:
                option_b.append((f, x, k, res))
                # print 'B:',f,x,k, res
            else:
                option_b.append((f, x, k, None))

        xorstrings = []
        if None not in map(lambda y: y[3], option_a):
            xorstrings = option_a
        elif None not in map(lambda z: z[3], option_b):
            xorstrings = option_b

        for f, x, k, r in xorstrings:
            if r is not None:
                output = output.replace(f, b'"' + r + b'"')

        if output == text:
            return None
        return output

    @staticmethod
    def xor_with_key(s: bytes, k: bytes) -> bytes:
        """ XOR s using the key k """
        return bytes([a ^ b for a, b in zip(s, (len(s) // len(k) + 1) * k)])

    @staticmethod
    def zp_xor_with_key(s: bytes, k: bytes) -> bytes:
        """ XOR variant where xoring is skipped for 0 bytes and when the byte is equal to the keybyte """
        return bytes([a if a in (0, b) else a ^ b for a, b in zip(s, (len(s) // len(k) + 1) * k)])

    @staticmethod
    def clean_up_final_layer(text: bytes) -> bytes:
        """ Remove deobfuscripter artifacts from final layer for display """
        output = regex.sub(rb'\r', b'', text)
        output = regex.sub(rb'<deobsfuscripter:[^>]+>\n?', b'', output)
        return output

    # noinspection PyBroadException
    def extract_htmlscript(self, text: bytes) -> List[bytes]:
        """ Extract scripts from html """
        objects = []
        try:
            for tag_type in ['object', 'embed', 'script']:
                for s in BeautifulSoup(text, 'lxml').find_all(tag_type):
                    objects.append(str(s).encode('utf-8'))
        except Exception as e:
            self.log.warning(f"Failure in extract_htmlscript function: {str(e)}")
            objects = []
        return objects

    # --- Execute --------------------------------------------------------------------------------------------------

    def execute(self, request: ServiceRequest) -> None:
        # --- Setup ----------------------------------------------------------------------------------------------
        request.result = Result()
        md = DecoderWrapper(self.working_directory)

        max_attempts = 100 if request.deep_scan else 10

        # --- Prepare Techniques ----------------------------------------------------------------------------------
        first_pass: TechniqueList = [
            ('MSOffice Embedded script', self.msoffice_embedded_script_string),
            ('Powershell carets', self.powershell_carets),
            ('Array of strings', self.array_of_strings),
            ('Fake array vars', self.vars_of_fake_arrays),
            ('Simple XOR function', self.simple_xor_function),
        ]
        second_pass: TechniqueList = [
            ('MSWord macro vars', self.mswordmacro_vars),
            ('Powershell vars', self.powershell_vars),
            ('Charcode hex', self.charcode_hex),
            ('XML unescape', self.xml_unescape)
        ]
        second_pass.extend(first_pass)
        final_pass: TechniqueList = [
            ('Charcode', self.charcode),
        ]
        final_pass.extend(second_pass)

        code_extracts = [
            ('.*html.*', "HTML scripts extraction", self.extract_htmlscript)
        ]

        layer = request.file_contents

        # --- Stage 1: Script Extraction --------------------------------------------------------------------------
        extract_res = ResultSection("Extraction")
        for pattern, name, func in code_extracts:
            if regex.match(regex.compile(pattern), request.task.file_type):
                extracted_parts = func(request.file_contents)
                layer = b"\n".join(extracted_parts).strip()
                extract_res.add_line(name)
                break
        if len(layer.strip()) < 2:
            return  # No script present in file
        if request.file_type == 'code/ps1':
            sig = regex.search(
                rb'# SIG # Begin signature block\r\n(?:# [A-Za-z0-9+/=]+\r\n)+# SIG # End signature block',
                request.file_contents)
            if sig:
                layer = layer[:sig.start()] + layer[sig.end():]
                lines = sig.group().split(b'\r\n# ')
                base64 = b''.join(line.strip() for line in lines[1:-1])
                try:
                    # Extract signature
                    signature = binascii.a2b_base64(base64)
                    sig_filename = 'powershell_signature'
                    sig_path = os.path.join(self.working_directory, sig_filename)
                    with open(sig_path, 'wb+') as f:
                        f.write(signature)
                    request.add_extracted(sig_path, sig_filename, "Powershell Signature")
                    extract_res.add_line(f"Powershell Signature Comment, see {sig_filename}")
                except binascii.Error:
                    pass
        if extract_res.body:
            request.result.add_section(extract_res)

        # Save extracted scripts before deobfuscation
        before_deobfuscation = layer

        # --- Stage 2: Deobsfucation ------------------------------------------------------------------------------
        passes: dict[int, tuple[list[str], dict[str, set[bytes]]]] = {}
        techniques = first_pass
        n_pass = 0  # Ensure n_pass is bound outside of the loop
        for n_pass in range(max_attempts):
            layer, techiques_used, iocs = self._deobfuscripter_pass(layer, techniques, md)
            if techiques_used:
                passes[n_pass] = techiques_used, iocs  # Store the techniques used and iocs found for each pass
            else:
                # If there are no new layers in a pass, start second pass or break
                if len(techniques) != len(first_pass):
                    # Already on second pass
                    break
                techniques = second_pass

        # --- Final Layer -----------------------------------------------------------------------------------------
        layer, final_techniques, final_iocs = self._deobfuscripter_pass(layer, final_pass, md, final=True)
        if final_techniques:
            passes[n_pass+1] = final_techniques, final_iocs

        # --- Compiling results -----------------------------------------------------------------------------------
        if request.get_param('extract_original_iocs'):
            pat_values = get_tree_tags(md.multidecoder.scan(before_deobfuscation, 1))
            ioc_res = ResultSection("The following IOCs were found in the original file", parent=request.result,
                                    body_format=BODY_FORMAT.MEMORY_DUMP)
            for k, val in pat_values.items():
                for v in val:
                    if ioc_res:
                        ioc_res.add_line(f"Found {k.upper().replace('.', ' ')}: {safe_str(v)}")
                        ioc_res.add_tag(k, v)

        if not passes:
            return
        # Cleanup final layer
        clean = self.clean_up_final_layer(layer)
        if clean == request.file_contents:
            return

        # Display obfuscation steps
        heuristic = Heuristic(1)
        mres = ResultSection("De-obfuscation steps taken by DeobsfuScripter",
                             parent=request.result,
                             heuristic=heuristic)

        tech_count = Counter()
        for p in passes.values():
            tech_count.update(p[0])
        for tech, count in tech_count.items():
            heuristic.add_signature_id(tech, frequency=count)
            mres.add_line(f"{tech}, {count} time(s).")

        # Filter for new IOCs
        seen_iocs = set()
        for n_pass, (_, iocs) in passes.items():
            for ioc_type in iocs:
                new_iocs = set()
                for ioc in iocs[ioc_type]:
                    prefix = b'/'.join(ioc.split(b'/', 3)[:3]) if ioc_type == 'network.static.uri' else ioc
                    if prefix not in seen_iocs and prefix not in before_deobfuscation:
                        new_iocs.add(ioc)
                        seen_iocs.add(ioc)
                iocs[ioc_type] = new_iocs
        # And for new reversed IOCs
        rev_iocs = md.ioc_tags(clean[::-1])
        reversed_file = before_deobfuscation[::-1]
        for ioc_type in rev_iocs:
            for ioc in rev_iocs[ioc_type]:
                new_iocs = set()
                prefix = b'/'.join(ioc.split(b'/', 3)[:3]) if ioc_type == 'network.static.uri' else ioc
                if prefix not in seen_iocs and prefix not in reversed_file:
                    new_iocs.add(ioc)
                    seen_iocs.add(ioc)
                rev_iocs[ioc_type] = new_iocs

        # Display final layer
        byte_count = 5000
        if request.deep_scan or (len(clean) > 1000 and heuristic.score >= 500) or seen_iocs:
            # Save extracted file
            byte_count = 500
            file_name = f"{os.path.basename(request.file_name)}_decoded_final"
            file_path = os.path.join(self.working_directory, file_name)
            # Ensure directory exists before write
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'wb+') as f:
                f.write(clean)
                self.log.debug(f"Submitted dropped file for analysis: {file_path}")
            request.add_extracted(file_path, file_name, "Final deobfuscation layer")

        ResultSection(f"First {byte_count} bytes of the final layer:", body=safe_str(clean[:byte_count]),
                      body_format=BODY_FORMAT.MEMORY_DUMP, parent=request.result)

        # Report new IOCs
        new_ioc_res = ResultSection("New IOCs found after de-obfustcation",
                                    body_format=BODY_FORMAT.MEMORY_DUMP)
        heuristic = 0
        for n_pass, (_, iocs) in passes.items():
            if not iocs:
                continue
            new_ioc_res.add_line("New IOCs found in pass {n_pass}:")
            for ioc_type in iocs:
                for ioc in iocs[ioc_type]:
                    if n_pass == 0:  # iocs in the first pass can be found by other services
                        heuristic = 5
                    elif heuristic < 7:
                        heuristic = 7 if 'network' in ioc_type and ioc_type != 'network.static.domain' else 6
                    new_ioc_res.add_line(f"Found {ioc_type.upper().replace('.', ' ')}: {safe_str(ioc)}")
                    new_ioc_res.add_tag(ioc_type, ioc)
        if rev_iocs:
            new_ioc_res.add_line("New IOCs found reversed in the final layer:")
            for ioc_type in rev_iocs:
                for ioc in rev_iocs[ioc_type]:
                    heuristic = max(7 if 'network' in ioc_type and ioc_type != 'network.static.domain'
                                    else 6, heuristic)
                    new_ioc_res.add_line(f"Found {ioc_type.upper().replace('.', ' ')}: {safe_str(ioc)}")
                    new_ioc_res.add_tag(ioc_type, ioc)
        if heuristic > 0:
            new_ioc_res.set_heuristic(heuristic)
        if new_ioc_res.body:
            request.result.add_section(new_ioc_res)

        # Report extracted files
        if md.extracted_files:
            ext_file_res = ResultSection("The following files were extracted during the deobfuscation",
                                         heuristic=Heuristic(8), parent=request.result)
            for extracted in md.extracted_files:
                file_name = os.path.basename(extracted)
                try:
                    if request.add_extracted(extracted, file_name, "File of interest deobfuscated from sample",
                                             safelist_interface=self.api_interface):
                        ext_file_res.add_line(file_name)
                except MaxExtractedExceeded:
                    self.log.warning('Extraction limit exceeded while adding files of interest.')
                    break

    @staticmethod
    def _deobfuscripter_pass(layer: bytes,
                             techniques: TechniqueList,
                             md: DecoderWrapper,
                             final=False) -> tuple[bytes, list[str], dict]:
        techniques_used = []
        for name, technique in techniques:
            result = technique(layer)
            if result:
                techniques_used.append(name)
                # Looks like it worked, continue with the new layer
                layer = result
        # Use multidecoder techniques and ioc tagging
        if final:
            tree = md.multidecoder.scan(layer)
        else:
            tree = md.multidecoder.scan(layer, depth=1)
        md.extract_files(tree, 500)
        techniques_used.extend(obfuscation_counts(tree).keys())
        iocs = get_tree_tags(tree)  # Get IoCs for the pass
        layer = squash_replace(layer, tree)
        return layer, techniques_used, iocs
