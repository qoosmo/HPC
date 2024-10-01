package src;

import java.util.Arrays;

import javax.crypto.SecretKey;

public class StartEndPoint {
	
	
	SecretKey sp;
	byte [] ep;
	public SecretKey getSp() {
		return sp;
	}
	public void setSp(SecretKey sp) {
		this.sp = sp;
	}
	public byte[] getEp() {
		return ep;
	}
	public void setEp(byte[] ep) {
		this.ep = ep;
	}
	@Override
	public String toString() {
		return "StartEndPoint [sp=" +  Arrays.toString(sp.getEncoded()) + ", ep=" + Arrays.toString(ep) + "]";
	}
	public StartEndPoint(SecretKey sp, byte[] ep) {
		super();
		this.sp = sp;
		this.ep = ep;
	}
	

}
