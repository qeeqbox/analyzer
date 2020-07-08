function check_task(task) {
    $.ajaxSetup({
        headers: {
            "X-CSRFToken": csrf_token
        }
    });
    $.ajax({
        type: "POST",
        url: "/task",
        data: JSON.stringify({
            "uuid": task
        }),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        success: function(_task) {
            parsed = JSON.stringify(_task)
            if (_task["Task"] === "") {
                setTimeout(function() {
                    check_task(task);
                }, 1000)
            } else {
                window.location.replace("/reportshtml/api/file/?id=" + _task["Task"] + "&coll=fs");
            }
        },
    });
}