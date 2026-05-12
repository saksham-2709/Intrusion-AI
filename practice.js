

let x = 49;
function nikhil() {
 return new Promise((resolve,reject) =>{
    if (x == 49){
        resolve("i am learning");
    }
    else{
        reject("i am useless")
    }
 });
}

async function radhika() {
    try {
        const user = await nikhil();
        console.log(user);
        console.log("function working");

    }
    catch(err){
        console.log("i am not worth it");
    }
    
}
radhika();