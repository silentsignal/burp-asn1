package burp;

import java.util.*;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory
{
	IBurpExtenderCallbacks callbacks;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		callbacks.setExtensionName("ASN.1 toolbox");
		callbacks.registerMessageEditorTabFactory(this);
		this.callbacks = callbacks;
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new Asn1Editor(callbacks);
	}
}
