package burp;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.*;
import java.util.*;
import java.util.regex.*;

import javax.swing.*;

import org.apache.commons.io.IOUtils;

public class Asn1Editor implements IMessageEditorTab
{
	private final ITextEditor textEditor;
	private byte[] content;
	private final IExtensionHelpers helpers;
	private final IBurpExtenderCallbacks callbacks;

	Asn1Editor(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		textEditor = callbacks.createTextEditor();
		textEditor.setEditable(false);
	}

	public boolean isEnabled(byte[] content, boolean isRequest) {
		return tryDecode(content, isRequest) != null;
	}

	private byte[] tryDecode(byte[] content, boolean isRequest) {
		if (content.length == 0) return null;

		int bodyOffset;
		if (isRequest) {
			IRequestInfo req = helpers.analyzeRequest(content);
			bodyOffset = req.getBodyOffset();
		} else {
			IResponseInfo i = helpers.analyzeResponse(content);
			bodyOffset = i.getBodyOffset();
		}
		int payloadLength = content.length - bodyOffset;
		if (payloadLength >= 3 && content[bodyOffset] == 'M' &&
				content[bodyOffset + 1] == 'I' && content[bodyOffset + 2] >= 'G' &&
				content[bodyOffset + 2] <= 'I') {
			byte[] payload = new byte[payloadLength];
			System.arraycopy(content, bodyOffset, payload, 0, payloadLength);
			return helpers.base64Decode(payload);
		}
		return null;
	}

	private void debug(String s) {
		// XXX remove XXX
		try {
			callbacks.getStderr().write(helpers.stringToBytes(s + "\n"));
		} catch (Exception e) {

		}
	}

	private final static Collection<String> ASN1PARSE_CMD = Arrays.asList(
			"openssl", "asn1parse", "-inform", "DER", "-i");

	public void setMessage(byte[] content, boolean isRequest) {
		this.content = content;
		if (content == null) return;
		byte[] msg = tryDecode(content, isRequest);
		if (msg == null) return;
		StringBuilder sb = new StringBuilder(msg.length);
		try {
			parseAsn1(msg, sb, new int[0]);
		} catch (Exception e) {
			sb.append("OpenSSL error: " + e.getMessage());
		}
		textEditor.setText(helpers.stringToBytes(sb.toString()));
	}

	private Pattern APPL_RE = Pattern.compile("^ *(\\d+):.+?hl=(\\d+).+?appl", Pattern.MULTILINE);
	private Pattern HEX_RE = Pattern.compile("\\[HEX DUMP\\]:([0-9A-F]+)");

	private void parseAsn1(byte[] msg, StringBuilder sb, int[] offsets) throws IOException, InterruptedException {
		ArrayList<String> cmd = new ArrayList(ASN1PARSE_CMD);
		if (offsets.length > 0) {
			sb.append("\nParsing at offset(s)");
			for (int offset : offsets) {
				String offsetString = String.valueOf(offset);
				cmd.add("-strparse");
				cmd.add(offsetString);
				sb.append(' ').append(offsetString);
			}
			sb.append("\n\n");
		}
		Process asn1parse = Runtime.getRuntime().exec(cmd.toArray(new String[cmd.size()]));
		try (OutputStream stdin = asn1parse.getOutputStream()) {
			stdin.write(msg);
		}
		String output, errors;
		try (InputStream stdout = asn1parse.getInputStream()) {
			output = helpers.bytesToString(IOUtils.toByteArray(stdout));
		}
		try (InputStream stderr = asn1parse.getErrorStream()) {
			errors = helpers.bytesToString(IOUtils.toByteArray(stderr));
		}
		sb.append(output);
		sb.append(errors);
		asn1parse.waitFor();
		Matcher m = APPL_RE.matcher(output);
		int start = 0;
		while (m.find(start)) {
			int offset = Integer.parseInt(m.group(1));
			int headerLength = Integer.parseInt(m.group(2));
			int[] subOffsets = Arrays.copyOf(offsets, offsets.length + 1);
			subOffsets[offsets.length] = offset + headerLength;
			parseAsn1(msg, sb, subOffsets);
			start = m.end();
		}
		m = HEX_RE.matcher(output);
		start = 0;
		while (m.find(start)) {
			hexDump(m.group(1), sb);
			start = m.end();
		}
	}

	public static void main(String[] args) {
		StringBuilder sb = new StringBuilder();
		hexDump(args[0], sb);
		System.out.print(sb.toString());
	}

	private static void hexDump(String hex, StringBuilder sb) {
		sb.append("\nFriendlier hex dump\n\n");
		int octets = hex.length() / 2;
		for (int offset = 0; offset < octets; offset++) {
			if ((offset & 0x7) == 0) {
				if ((offset & 0xf) == 0) {
					hexDumpFrame(hex, sb, offset - 16, offset, false);
				}
				sb.append(' ');
			}
			String hexOctet = hex.substring(offset * 2, offset * 2 + 2);
			sb.append(' ').append(hexOctet);
		}
		hexDumpFrame(hex, sb, octets & ~0xf, octets, true);
		sb.append('\n');
	}

	private static void hexDumpFrame(String hex, StringBuilder sb, int offset, int nextOffset, boolean last) {
		int octets = hex.length() / 2;
		int end = Math.min(octets, offset + 16);
		if (offset >= 0) {
			if (last) {
				int missing = ((nextOffset & 0xf) ^ 0xf) + 1;
				if (missing < 16) {
					if (missing >= 8) sb.append(' ');
					for (int i = 0; i < missing; i++) {
						sb.append("   ");
					}
				} else {
					offset -= 16;
				}
			}
			sb.append("  |");
			for (int i = offset; i < end; i++) {
				String hexOctet = hex.substring(i * 2, i * 2 + 2);
				byte b = (byte)(Short.parseShort(hexOctet, 16));
				sb.append(b >= 0x20 && b <= 0x7f ? (char)b : '.');
			}
			sb.append("|\n");
		}
		sb.append(String.format("%08x", nextOffset));
	}

	public String getTabCaption() { return "ASN.1"; }
	public Component getUiComponent() { return textEditor.getComponent(); }
	public byte[] getMessage() { return content; }
	public boolean isModified() { return false; }
	public byte[] getSelectedData() { return null; }
}
