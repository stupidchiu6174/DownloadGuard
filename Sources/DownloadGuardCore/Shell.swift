import Foundation

/// 執行外部指令並收集輸出。逾時就終止,不會卡住掃描。
enum Shell {
    struct Result {
        var status: Int32
        var stdout: String
        var stderr: String
        var timedOut: Bool
    }

    @discardableResult
    static func run(_ tool: String, _ args: [String], input: String? = nil,
                    timeout: TimeInterval = 30, maxOutput: Int = 2_000_000) -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        let inPipe = Pipe()
        p.standardInput = inPipe

        // 兩條管線都要邊跑邊讀,不然輸出塞滿緩衝區時子程序會卡住
        let lock = NSLock()
        var outData = Data(), errData = Data()
        out.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            if d.isEmpty { h.readabilityHandler = nil; return }
            lock.lock(); if outData.count < maxOutput { outData.append(d) }; lock.unlock()
        }
        err.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            if d.isEmpty { h.readabilityHandler = nil; return }
            lock.lock(); if errData.count < maxOutput { errData.append(d) }; lock.unlock()
        }

        let done = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in done.signal() }
        do { try p.run() } catch {
            return Result(status: -1, stdout: "", stderr: error.localizedDescription, timedOut: false)
        }
        if let input { inPipe.fileHandleForWriting.write(Data(input.utf8)) }
        try? inPipe.fileHandleForWriting.close()

        var timedOut = false
        if done.wait(timeout: .now() + timeout) == .timedOut {
            timedOut = true
            p.terminate()
            if done.wait(timeout: .now() + 2) == .timedOut { kill(p.processIdentifier, SIGKILL); done.wait() }
        }
        out.fileHandleForReading.readabilityHandler = nil
        err.fileHandleForReading.readabilityHandler = nil
        // 收尾:把還留在管線裡的資料讀完
        let restOut = out.fileHandleForReading.readDataToEndOfFile()
        let restErr = err.fileHandleForReading.readDataToEndOfFile()
        lock.lock()
        outData.append(restOut); errData.append(restErr)
        let o = String(decoding: outData.prefix(maxOutput), as: UTF8.self)
        let e = String(decoding: errData.prefix(maxOutput), as: UTF8.self)
        lock.unlock()
        return Result(status: p.terminationStatus, stdout: o, stderr: e, timedOut: timedOut)
    }
}
