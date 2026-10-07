// A client's promise includes its original process cleanup. Join it together
// with the server before the caller can release either process's artifacts.
export async function finishExampleProcesses(client, controller, finishServer, failure) {
  controller.abort(failure ?? new Error("example process scope finished"));
  const results = await Promise.allSettled([client, finishServer()]);
  const failures = results.filter(result => result.status === "rejected").map(result => result.reason);
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, "example client and server failed");
}
