#include "resource.h"
#include <windows.h>

#include <Shlobj.h>
#include <Shellapi.h>
#include <shobjidl.h>
#include <Shlwapi.h>
#include <tchar.h>
#include <propkey.h>
#pragma comment(lib, "shlwapi.lib")

#define SUSIE_EXT	"_SF"
#define FILE_HEADER	"_SF"
#define FILE_HEADER_SIZE 3

#define	SIZE_BUFF 32768
#define	CACHE_ITEMS 65536
#define MAX_CSIDL				256
#define E_CANCELLED         HRESULT_FROM_WIN32(ERROR_CANCELLED)
#define E_FILE_NOT_FOUND    HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
#define E_PATH_NOT_FOUND    HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)
#define E_NOT_READY         HRESULT_FROM_WIN32(ERROR_NOT_READY)
#define E_BAD_NETPATH       HRESULT_FROM_WIN32(ERROR_BAD_NETPATH)
#define E_INVALID_PASSWORD  HRESULT_FROM_WIN32(ERROR_INVALID_PASSWORD)
// Susie Plug-in 関連の定義 ---------------------------------------------------
/*-------------------------------------------------------------------------*/
/* エラーコード */
/*-------------------------------------------------------------------------*/
#define SPI_NO_FUNCTION			-1	/* その機能はインプリメントされていない */
#define SPI_ALL_RIGHT			0	/* 正常終了 */
#define SPI_ABORT				1	/* コールバック関数が非0を返したので展開を中止した */
#define SPI_NOT_SUPPORT			2	/* 未知のフォーマット */
#define SPI_OUT_OF_ORDER		3	/* データが壊れている */
#define SPI_NO_MEMORY			4	/* メモリーが確保出来ない */
#define SPI_MEMORY_ERROR		5	/* メモリーエラー */
#define SPI_FILE_READ_ERROR		6	/* ファイルリードエラー */
#define	SPI_WINDOW_ERROR		7	/* 窓が開けない (非公開のエラーコード) */
#define SPI_OTHER_ERROR			8	/* 内部エラー */
#define	SPI_FILE_WRITE_ERROR	9	/* 書き込みエラー (非公開のエラーコード) */
#define	SPI_END_OF_FILE			10	/* ファイル終端 (非公開のエラーコード) */

//-------------------------------------- DLL 定数
typedef ULONG_PTR susie_time_t;
//-------------------------------------- DLL 構造体
#pragma pack(push,1)

typedef struct {
	unsigned char  method[8];	// 圧縮法の種類
	ULONG_PTR      position;	// ファイル上での位置
	ULONG_PTR      compsize;	// 圧縮されたサイズ
	ULONG_PTR      filesize;	// 元のファイルサイズ
	susie_time_t   timestamp;	// ファイルの更新日時
	char           path[200];	// 相対パス
	char           filename[200];	// ファイル名
	unsigned long  crc;	// CRC
	#ifdef _WIN64
	   // 64bit版の構造体サイズは444bytesですが、実際のサイズは
	   // アラインメントにより448bytesになります。環境によりdummyが必要です。
	   char        dummy[4];
	#endif
} SUSIE_FINFO;
#pragma pack(pop)

typedef struct {
	unsigned char	method[8];		// 圧縮法の種類
	ULONG_PTR		position;		// ファイル上での位置
	ULONG_PTR		compsize;		// 圧縮されたサイズ
	ULONG_PTR		filesize;		// 元のファイルサイズ
	susie_time_t	timestamp;		// ファイルの更新日時
	WCHAR			path[200];		// 相対パス
	WCHAR			filename[200];	// ファイルネーム
	unsigned long	crc;			// CRC
}SUSIE_FINFOTW;

// コールバック
typedef int (__stdcall *SUSIE_PROGRESS)(int nNum,int nDenom,LONG_PTR lData);

//XP or higher.
typedef HRESULT (WINAPI* LPFNSHParseDisplayName)(LPCWSTR pszName, IBindCtx *pbc, PIDLIST_ABSOLUTE *ppidl, SFGAOF sfgaoIn, SFGAOF *psfgaoOut);
