#pragma once
class CScanGraph
{
public:
	CScanGraph();
	~CScanGraph();

	void GetScanGraphData(LPUScanGraphInfo pdwScanGraphData);
private:
	bool DateTimeForUI(ULONG64 ulDate, DWORD dwTime, LPTSTR szDateTime, SIZE_T cchDateTime);
};

