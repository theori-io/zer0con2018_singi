function setAddr64( addr, offset )
{
	return { low:addr.low+offset, high:addr.high };
}

function print64(string, addr)
{
	document.write( string, addr.high.toString(16) + addr.low.toString(16) + "<br>");
}

function i2s64(v)
{
	var values = [v.low,v.high];
	var res = "";
	for(i=0;i<values.length;i++)
	{
		res += String.fromCharCode((values[i] & 0x000000ff) >>> 0);
		res += String.fromCharCode((values[i] & 0x0000ff00) >>> 8);
		res += String.fromCharCode((values[i] & 0x00ff0000) >>> 16);
		res += String.fromCharCode((values[i] & 0xff000000) >>> 24);
	}
	return res;
}
