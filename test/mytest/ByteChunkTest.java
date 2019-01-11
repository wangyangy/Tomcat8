package mytest;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.tomcat.util.buf.ByteChunk;


public class ByteChunkTest implements ByteChunk.ByteOutputChannel{

	private ByteChunk fileBuffer ;
	
	private FileOutputStream fos;

	@Override
	public void realWriteBytes(byte[] buf, int off, int len) throws IOException {
		fos.write(buf,off,len);
	}


	public ByteChunkTest() {
		fileBuffer = new ByteChunk();
		//设置缓冲区的初始大小3,最大值为7
		fileBuffer.allocate(3, 7);
		fileBuffer.setByteOutputChannel(this);
		try {
			fos = new FileOutputStream(new File("d://test_.txt"));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	
	public int doWrite(byte []bys) throws IOException {
		for(int i=0;i<bys.length;i++) {
			fileBuffer.append(bys[i]);
		}
		return bys.length;
	}
	
	public void flush() throws IOException {
		fileBuffer.flushBuffer();
	}

	public ByteChunk getFileBuffer() {
		return fileBuffer;
	}


	public void setFileBuffer(ByteChunk fileBuffer) {
		this.fileBuffer = fileBuffer;
	}


	public static void main(String[] args) throws InterruptedException {
		byte []bys = "12345678".getBytes();
		System.out.println(bys.length);
		ByteChunkTest t = new ByteChunkTest();
		try {
			t.doWrite(bys);
			Thread.sleep(1000*10);
			t.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}


}
