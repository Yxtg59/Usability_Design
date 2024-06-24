<!-- eslint-disable vue/no-ref-as-operand -->
<!-- eslint-disable vue/no-ref-as-operand -->
<!-- eslint-disable vue/no-ref-as-operand -->
<!-- eslint-disable no-unused-vars -->
<template>
       <div>
        <div class="chat-icon" @click="toggleChatbot">
            <img src="../assets/lading/boot.gif" alt="Chatbot">
        </div>

        <div class="chatbot-container" v-if="showChatbot">
            <iframe
                allow="microphone;"
                width="350"
                height="430"
                src="https://console.dialogflow.com/api-client/demo/embedded/3b64b79b-91fa-4192-a1fc-ef84c7fbddf4">
            </iframe>
        </div>
    </div>
            <div class="col-sm-12">
           
                <p></p>
                <h1>Lista de chequeo - Heurísticas usabilidad  {{ owner.name }}</h1>
                <label for="exampleDataList" class="form-label">A continuación se presenta el Checklist de análisis
                    heurístico, con el fin de conocer qué principios heurísticos están cumpliendo dentro de su
                    plataforma.</label>
                <div class="container mt-5">
                    <!-- Enlace bonito con clases de Bootstrap -->
                    <p>Ve al sigueinte enlace para realizar evaluacion</p>
                    <p style="color:blue;">{{ url }}</p>
                    <a :href="url" class="btn btn-primary btn-lg" target="_blank">Ir al enlace</a>
                </div>
                <h4>H1 - Visibilidad del estado del sistema</h4>
                <div class="form-check form-switch">
                    <label for="switchH01P01" class="form-label">El sistema indica la sección donde se encuentra actualmente
                        el usuario: </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH01P01"
                        v-model="Heuristics.H01P01">
                    <label class="form-check-label" for="switchH01P01">{{ Heuristics.H01P01 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH01P02" class="form-label">El sistema informa acerca del estado actual de un
                        proceso/tarea. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH01P02"
                        v-model="Heuristics.H01P02">
                    <label class="form-check-label" for="switchH01P02">{{ Heuristics.H01P02 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH01P03" class="form-label">La transición de un estado a otro es fácilmente
                        perceptible. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH01P03"
                        v-model="Heuristics.H01P03">
                    <label class="form-check-label" for="switchH01P03">{{ Heuristics.H01P03 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH01P04" class="form-label">El sistema muestra claramente las reacciones a las acciones
                        del usuario. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH01P04"
                        v-model="Heuristics.H01P04">
                    <label class="form-check-label" for="switchH01P04">{{ Heuristics.H01P04 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH01P05" class="form-label">El sistema muestra claramente las reacciones a las acciones
                        del usuario. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH01P05"
                        v-model="Heuristics.H01P05">
                    <label class="form-check-label" for="switchH01P05">{{ Heuristics.H01P05 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH01P06" class="form-label">Los tiempos de respuesta son razonables. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH01P06"
                        v-model="Heuristics.H01P06">
                    <label class="form-check-label" for="switchH01P05">{{ Heuristics.H01P06 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH01P07" class="form-label">Una opción seleccionada se destaca claramente respecto a
                        otras. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH01P07"
                        v-model="Heuristics.H01P07">
                    <label class="form-check-label" for="switchH01P05">{{ Heuristics.H01P07 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="mb-3">
                    <label for="exampleFormControlTextarea1" class="form-label">Observaciones</label>
                    <textarea class="form-control" id="exampleFormControlTextarea1" rows="3"
                        v-model="Heuristics.OBSERVACIONH1"></textarea>
                </div>


                <!-- H2 AQUI -->

                <h4>H2 - Relación entre el sistema y el mundo real</h4>
                <div class="form-check form-switch">
                    <label for="switchH02P01" class="form-label">El sistema usa palabras, frases y conceptos familiares al
                        usuario. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH02P01"
                        v-model="Heuristics.H02P01">
                    <label class="form-check-label" for="switchH02P01">{{ Heuristics.H02P01 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH02P02" class="form-label">La información es presentada de forma simple, natural y en
                        orden lógico. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH02P02"
                        v-model="Heuristics.H02P02">
                    <label class="form-check-label" for="switchH02P02">{{ Heuristics.H02P02 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH02P03" class="form-label">El sistema está diseñado en el idioma que indica. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH02P03"
                        v-model="Heuristics.H02P03">
                    <label class="form-check-label" for="switchH02P03">{{ Heuristics.H02P03 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH02P04" class="form-label">La secuencia de pasos de los procesos sigue el modelo metal
                        de los usuarios. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH02P04"
                        v-model="Heuristics.H02P04">
                    <label class="form-check-label" for="switchH02P04">{{ Heuristics.H02P04 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH02P05" class="form-label">El sistema utiliza metáforas y controles de interfaz que
                        corresponden con la realidad. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH02P05"
                        v-model="Heuristics.H02P05">
                    <label class="form-check-label" for="switchH02P05">{{ Heuristics.H02P05 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH02P06" class="form-label">Las metáforas son fáciles de comprender. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH02P06"
                        v-model="Heuristics.H02P06">
                    <label class="form-check-label" for="switchH02P06">{{ Heuristics.H02P06 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH02P07" class="form-label">Los controles de interfaz importantes se presentan en la
                        pantalla. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH02P07"
                        v-model="Heuristics.H02P07">
                    <label class="form-check-label" for="switchH02P07">{{ Heuristics.H02P07 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH02P08" class="form-label">En la aplicación se explican elementos complejos. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH02P08"
                        v-model="Heuristics.H02P08">
                    <label class="form-check-label" for="switchH02P08">{{ Heuristics.H02P08 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="mb-3">
                    <label for="exampleFormControlTextarea1" class="form-label">Observaciones</label>
                    <textarea class="form-control" id="exampleFormControlTextarea1" rows="3"
                        v-model="Heuristics.OBSERVACIONH2"></textarea>
                </div>

                <!-- H3 AQUI -->

                <h4>H3 - Control y libertad de usuario</h4>
                <div class="form-check form-switch">
                    <label for="switchH03P01" class="form-label">Es posible deshacer una acción cuando ésta es una función o
                        genera alguna operación. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH03P01"
                        v-model="Heuristics.H03P01">
                    <label class="form-check-label" for="switchH03P01">{{ Heuristics.H03P01 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH03P02" class="form-label">En caso de realizar una transacción que posee varios pasos,
                        es posible  pasos anteriores del proceso para modificarlos. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH03P02"
                        v-model="Heuristics.H03P02">
                    <label class="form-check-label" for="switchH03P02">{{ Heuristics.H03P02 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH03P04" class="form-label">Existe una salida de emergencia al realizar algún proceso
                        (Cancelar desconecta, va
                        al inicio). </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH03P04"
                        v-model="Heuristics.H03P03">
                    <label class="form-check-label" for="switchH03P04">{{ Heuristics.H03P03 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH03P05" class="form-label">No se inician de forma automática acciones que no han sido
                        seleccionadas por el
                        usuario. Por ejemplo, la reproducción de un vídeo. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH03P05"
                        v-model="Heuristics.H03P04">
                    <label class="form-check-label" for="switchH03P05">{{ Heuristics.H03P04 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH03P06" class="form-label">Es posible guardar la información relacionada a una
                        transacción, sea exitosa o no. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH03P06"
                        v-model="Heuristics.H03P05">
                    <label class="form-check-label" for="switchH03P06">{{ Heuristics.H03P05 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH03P07" class="form-label">Existe un vínculo para regresar a la página de inicio.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH03P07"
                        v-model="Heuristics.H03P06">
                    <label class="form-check-label" for="switchH03P07">{{ Heuristics.H03P06 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="mb-3">
                    <label for="exampleFormControlTextarea1" class="form-label">Observaciones</label>
                    <textarea class="form-control" id="exampleFormControlTextarea1" rows="3"
                        v-model="Heuristics.OBSERVACIONH3"></textarea>
                </div>

                <!-- H4 AQUI -->

                <h4>H4 - Consistencia y Estándares</h4>
                <div class="form-check form-switch">
                    <label for="switchH04P01" class="form-label">Las etiquetas de vínculos tienen nombres iguales que los
                        títulos de la página a
                        los que redirige. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P01"
                        v-model="Heuristics.H04P01">
                    <label class="form-check-label" for="switchH04P01">{{ Heuristics.H04P01 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH04P02" class="form-label">Las mismas acciones llevan a los mismos resultados. Por
                        ejemplo, al ingresar a
                        una sección desde distintas partes del sistema, éstas se dirigen a la misma. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P02"
                        v-model="Heuristics.H04P02">
                    <label class="form-check-label" for="switchH04P02">{{ Heuristics.H04P02 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH04P03" class="form-label">Los elementos utilizados son similares en todo el sistema.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P03"
                        v-model="Heuristics.H04P03">
                    <label class="form-check-label" for="switchH04P03">{{ Heuristics.H04P03 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH04P04" class="form-label">Los controles de interfaz de diferentes pantallas se
                        emplean siempre del mismo
                        modo. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P04"
                        v-model="Heuristics.H04P04">
                    <label class="form-check-label" for="switchH04P04">{{ Heuristics.H04P04 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH04P05" class="form-label">El uso del vocabulario es consistente en todo el sistema.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P05"
                        v-model="Heuristics.H04P05">
                    <label class="form-check-label" for="switchH04P05">{{ Heuristics.H04P05 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH04P06" class="form-label">La misma información se muestra de la misma forma en todo
                        el sistema. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P06"
                        v-model="Heuristics.H04P06">
                    <label class="form-check-label" for="switchH04P06">{{ Heuristics.H04P06 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH04P07" class="form-label">La información está estructurada de forma similar en todo
                        el sistema.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P07"
                        v-model="Heuristics.H04P07">
                    <label class="form-check-label" for="switchH04P07">{{ Heuristics.H04P07 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH04P08" class="form-label">Las interfaces que conforman el sistema tienen un aspecto
                        visual coherente.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P08"
                        v-model="Heuristics.H04P08">
                    <label class="form-check-label" for="switchH04P08">{{ Heuristics.H04P08 ? 'SÍ' : 'NO' }}</label>
                </div>
                <div class="form-check form-switch">
                    <label for="switchH04P09" class="form-label">En situaciones similares se repiten secuencias de acciones.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P09"
                        v-model="Heuristics.H04P09">
                    <label class="form-check-label" for="switchH04P09">{{ Heuristics.H04P09 ? 'SÍ' : 'NO' }}</label>
                </div>
                <div class="form-check form-switch">
                    <label for="switchH04P010" class="form-label">Los símbolos utilizados son comprensibles y facilitan la
                        interacción con el
                        sistema.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P010"
                        v-model="Heuristics.H04P10">
                    <label class="form-check-label" for="switchH04P010">{{ Heuristics.H04P10 ? 'SÍ' : 'NO' }}</label>
                </div>
                <div class="form-check form-switch">
                    <label for="switchH04P011" class="form-label">Se usan colores estándares para vínculos (rojo para
                        advertencia, verde para
                        acción exitosa).
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P011"
                        v-model="Heuristics.H04P11">
                    <label class="form-check-label" for="switchH04P011">{{ Heuristics.H04P11 ? 'SÍ' : 'NO' }}</label>
                </div>
                <div class="form-check form-switch">
                    <label for="switchH04P12" class="form-label">Se siguen los estándares establecidos para los símbolos
                        utilizados (equis para
                        cancelar, etc.).
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P12"
                        v-model="Heuristics.H04P12">
                    <label class="form-check-label" for="switchH04P12">{{ Heuristics.H04P12 ? 'SÍ' : 'NO' }}</label>
                </div>
                <div class="form-check form-switch">
                    <label for="switchH04P13" class="form-label">La ubicación de las barras de navegación, herramientas de
                        búsquedas y controles
                        (botones) siguen los estándares comunes establecidos.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH04P13"
                        v-model="Heuristics.H04P13">
                    <label class="form-check-label" for="switchH04P13">{{ Heuristics.H04P13 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="mb-3">
                    <label for="exampleFormControlTextarea1" class="form-label">Observaciones</label>
                    <textarea class="form-control" id="exampleFormControlTextarea1" rows="3"
                        v-model="Heuristics.OBSERVACIONH4"></textarea>
                </div>

                <!-- H5 AQUI -->

                <h4>H5 - Prevención de Errores</h4>
                <div class="form-check form-switch">
                    <label for="switchH05P01" class="form-label">Se le pide confirmación al usuario antes de realizar una
                        acción crítica (eliminar,
                        aceptar, etc). </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH05P01"
                        v-model="Heuristics.H05P01">
                    <label class="form-check-label" for="switchH05P01">{{ Heuristics.H05P01 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH05P02" class="form-label">El sistema provee mensajes fáciles de entender que
                        previenen posibles errores. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH05P02"
                        v-model="Heuristics.H05P02">
                    <label class="form-check-label" for="switchH05P02">{{ Heuristics.H05P02 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH05P03" class="form-label">El sistema ofrece métodos de selección a los usuarios como
                        alternativas para el
                        ingreso datos.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH05P03"
                        v-model="Heuristics.H05P03">
                    <label class="form-check-label" for="switchH05P03">{{ Heuristics.H05P03 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH05P04" class="form-label">Los campos de entrada de datos contienen valores por
                        defecto cuando
                        corresponde. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH05P04"
                        v-model="Heuristics.H05P04">
                    <label class="form-check-label" for="switchH05P04">{{ Heuristics.H05P04 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH05P05" class="form-label">Todos los datos de entrada son validados.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH05P05"
                        v-model="Heuristics.H05P05">
                    <label class="form-check-label" for="switchH05P05">{{ Heuristics.H05P05 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="mb-3">
                    <label for="exampleFormControlTextarea1" class="form-label">Observaciones</label>
                    <textarea class="form-control" id="exampleFormControlTextarea1" rows="3"
                        v-model="Heuristics.OBSERVACIONH5"></textarea>
                </div>

                <!-- H6 AQUI -->

                <h4>H6 - Minimizar la carga de memoria del usuario</h4>
                <div class="form-check form-switch">
                    <label for="switchH06P01" class="form-label">Las opciones y/o funciones son fáciles de encontrar.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH06P01"
                        v-model="Heuristics.H06P01">
                    <label class="form-check-label" for="switchH06P01">{{ Heuristics.H06P01 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH06P02" class="form-label">Los principales controles de interfaz, están siempre
                        disponibles, visibles y son de
                        fácil acceso. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH06P02"
                        v-model="Heuristics.H06P02">
                    <label class="form-check-label" for="switchH06P02">{{ Heuristics.H06P02 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH06P03" class="form-label">Los campos de entrada de datos ya llenos mantienen la
                        información siempre
                        recordada.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH06P03"
                        v-model="Heuristics.H06P03">
                    <label class="form-check-label" for="switchH06P03">{{ Heuristics.H06P03 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="mb-3">
                    <label for="exampleFormControlTextarea1" class="form-label">Observaciones</label>
                    <textarea class="form-control" id="exampleFormControlTextarea1" rows="3"
                        v-model="Heuristics.OBSERVACIONH6"></textarea>
                </div>

                <!-- H7 AQUI -->

                <h4>H7 - Flexibilidad y eficiencia de uso</h4>
                <div class="form-check form-switch">
                    <label for="switchH07P01" class="form-label">Existen atajos para realizar tareas frecuentes.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH07P01"
                        v-model="Heuristics.H07P01">
                    <label class="form-check-label" for="switchH07P01">{{ Heuristics.H07P01 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH07P02" class="form-label">El sistema es personalizable, de acuerdo a las necesidades,
                        características,
                        preferencias personales, etc., de los usuarios. </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH07P02"
                        v-model="Heuristics.H07P02">
                    <label class="form-check-label" for="switchH07P02">{{ Heuristics.H07P02 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH07P03" class="form-label">El sistema no pide volver a ingresar información que ya ha
                        sido solicitada con
                        anterioridad.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH07P03"
                        v-model="Heuristics.H07P03">
                    <label class="form-check-label" for="switchH07P03">{{ Heuristics.H07P03 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH07P04" class="form-label">Las acciones que realiza el usuario toman mucho tiempo.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH07P04"
                        v-model="Heuristics.H07P04">
                    <label class="form-check-label" for="switchH07P04">{{ Heuristics.H07P04 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH07P05" class="form-label">El sistema informa al usuario si la ejecución de una acción
                        requiere mucho tiempo.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH07P05"
                        v-model="Heuristics.H07P05">
                    <label class="form-check-label" for="switchH07P05">{{ Heuristics.H07P05 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH07P06" class="form-label">Al rellenar un campo, las opciones disponibles se pueden
                        seleccionar sin tener
                        que escribirlas.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH07P06"
                        v-model="Heuristics.H07P06">
                    <label class="form-check-label" for="switchH07P06">{{ Heuristics.H07P06 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH07P07" class="form-label">La herramienta de búsqueda es visible en todo el sistema.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH07P07"
                        v-model="Heuristics.H07P07">
                    <label class="form-check-label" for="switchH07P07">{{ Heuristics.H07P07 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="mb-3">
                    <label for="exampleFormControlTextarea1" class="form-label">Observaciones</label>
                    <textarea class="form-control" id="exampleFormControlTextarea1" rows="3"
                        v-model="Heuristics.OBSERVACIONH7"></textarea>
                </div>

                <!-- H8 AQUI -->

                <h4>H8 - Diseño estético y minimalista</h4>
                <div class="form-check form-switch">
                    <label for="switchH08P01" class="form-label">La interfaz del sistema es simple.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH08P01"
                        v-model="Heuristics.H08P01">
                    <label class="form-check-label" for="switchH08P01">{{ Heuristics.H08P01 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH08P02" class="form-label">La interfaz del sistema está sobrecargada de información y
                        elementos que
                        distraen al usuario.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH08P02"
                        v-model="Heuristics.H08P02">
                    <label class="form-check-label" for="switchH08P02">{{ Heuristics.H08P02 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH08P03" class="form-label">Las alternativas que el usuario necesita para realizar una
                        tarea están visibles.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH08P03"
                        v-model="Heuristics.H08P03">
                    <label class="form-check-label" for="switchH08P03">{{ Heuristics.H08P03 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH08P04" class="form-label">La información presentada es simple, concisa y clara.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH08P04"
                        v-model="Heuristics.H08P04">
                    <label class="form-check-label" for="switchH08P04">{{ Heuristics.H08P04 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH08P05" class="form-label">La información visible es suficiente para realizar alguna
                        acción.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH08P05"
                        v-model="Heuristics.H08P05">
                    <label class="form-check-label" for="switchH08P05">{{ Heuristics.H08P05 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH08P06" class="form-label">Hay iconos o elementos gráficos abstractos.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH08P06"
                        v-model="Heuristics.H08P06">
                    <label class="form-check-label" for="switchH08P06">{{ Heuristics.H08P06 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH08P07" class="form-label">Hay iconos, controles, menús, gráficos, textos u otros
                        elementos redundantes.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH08P07"
                        v-model="Heuristics.H08P07">
                    <label class="form-check-label" for="switchH08P07">{{ Heuristics.H08P07 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH08P08" class="form-label">Hay elementos exclusivamente ornamentales.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH08P08"
                        v-model="Heuristics.H08P08">
                    <label class="form-check-label" for="switchH08P08">{{ Heuristics.H08P08 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH08P09" class="form-label">El sistema presenta información repetida.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH08P09"
                        v-model="Heuristics.H08P09">
                    <label class="form-check-label" for="switchH08P09">{{ Heuristics.H08P09 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH08P010" class="form-label">Los colores utilizados dan un contraste adecuado.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH08P010"
                        v-model="Heuristics.H08P10">
                    <label class="form-check-label" for="switchH08P010">{{ Heuristics.H08P10 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH08P011" class="form-label">Los elementos/secciones del sistema están distribuidos
                        correctamente en todo el
                        sistema.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH08P011"
                        v-model="Heuristics.H08P11">
                    <label class="form-check-label" for="switchH08P011">{{ Heuristics.H08P11 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="mb-3">
                    <label for="exampleFormControlTextarea1" class="form-label">Observaciones</label>
                    <textarea class="form-control" id="exampleFormControlTextarea1" rows="3"
                        v-model="Heuristics.OBSERVACIONH8"></textarea>
                </div>

                <!-- H9 AQUI -->

                <h4>H9 – Ayuda al usuario para reconocer, diagnosticar y recuperarse de errores</h4>
                <div class="form-check form-switch">
                    <label for="switchH09P01" class="form-label">Los mensajes de error son compresibles, escritos en
                        lenguaje común, sin códigos
                        o palabras técnicas.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH09P01"
                        v-model="Heuristics.H09P01">
                    <label class="form-check-label" for="switchH09P01">{{ Heuristics.H09P01 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH09P02" class="form-label">Los mensajes de error indican la causa del error.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH09P02"
                        v-model="Heuristics.H09P02">
                    <label class="form-check-label" for="switchH09P02">{{ Heuristics.H09P02 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH09P03" class="form-label">Los mensajes de error orientan al usuario para solucionar
                        el problema.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH09P03"
                        v-model="Heuristics.H09P03">
                    <label class="form-check-label" for="switchH09P03">{{ Heuristics.H09P03 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH09P04" class="form-label">Los mensajes de error utilizan una terminología y diseño
                        consistentes.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH09P04"
                        v-model="Heuristics.H09P04">
                    <label class="form-check-label" for="switchH09P04">{{ Heuristics.H09P04 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH09P05" class="form-label">Los mensajes de error están escritos en una forma
                        constructiva, de tal manera que
                        no atribuyen la culpa ni ofenden al usuario
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH09P05"
                        v-model="Heuristics.H09P05">
                    <label class="form-check-label" for="switchH09P05">{{ Heuristics.H09P05 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH09P06" class="form-label">Los mensajes de error usan palabras violentas u hostiles.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH09P06"
                        v-model="Heuristics.H09P06">
                    <label class="form-check-label" for="switchH09P06">{{ Heuristics.H09P06 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="mb-3">
                    <label for="exampleFormControlTextarea1" class="form-label">Observaciones</label>
                    <textarea class="form-control" id="exampleFormControlTextarea1" rows="3"
                        v-model="Heuristics.OBSERVACIONH9"></textarea>
                </div>

                <!-- H10 AQUI -->

                <h4>H10 – Ayuda y Documentación</h4>
                <div class="form-check form-switch">
                    <label for="switchH010P01" class="form-label">El sistema ofrece una ayuda clara y simple.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH010P01"
                        v-model="Heuristics.H10P01">
                    <label class="form-check-label" for="switchH010P01">{{ Heuristics.H10P01 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH010P02" class="form-label">La ayuda esta expresada en el lenguaje del usuario, libre
                        de jergas y modismos.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH010P02"
                        v-model="Heuristics.H10P02">
                    <label class="form-check-label" for="switchH010P02">{{ Heuristics.H10P02 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH010P03" class="form-label">La ayuda es fácil de encontrar, entender y aplicar.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH010P03"
                        v-model="Heuristics.H10P03">
                    <label class="form-check-label" for="switchH010P03">{{ Heuristics.H10P03 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH010P04" class="form-label">La ayuda siempre está visible y disponible.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH010P04"
                        v-model="Heuristics.H10P04">
                    <label class="form-check-label" for="switchH010P04">{{ Heuristics.H10P04 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH010P05" class="form-label">La estructura de la información de la ayuda se distingue
                        fácilmente.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH010P05"
                        v-model="Heuristics.H10P05">
                    <label class="form-check-label" for="switchH010P05">{{ Heuristics.H10P05 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH010P06" class="form-label">Las instrucciones de ayuda siguen la secuencia de acciones
                        a realizar por el
                        usuario para alcanzar una tarea.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH010P06"
                        v-model="Heuristics.H10P06">
                    <label class="form-check-label" for="switchH010P06">{{ Heuristics.H10P06 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH010P07" class="form-label">La interfaz de la ayuda es consistente con la interfaz de
                        todo el sistema.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH010P07"
                        v-model="Heuristics.H10P07">
                    <label class="form-check-label" for="switchH010P07">{{ Heuristics.H10P07 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH010P08" class="form-label">En la ayuda la información es fácil de encontrar.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH010P08"
                        v-model="Heuristics.H10P08">
                    <label class="form-check-label" for="switchH010P08">{{ Heuristics.H10P08 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="form-check form-switch">
                    <label for="switchH010P09" class="form-label">En el sistema existe ayuda contextual que guía al usuario
                        respecto al uso de los
                        elementos.
                    </label>
                    <input class="form-check-input" type="checkbox" role="switch" id="switchH010P09"
                        v-model="Heuristics.H10P09">
                    <label class="form-check-label" for="switchH010P09">{{ Heuristics.H10P09 ? 'SÍ' : 'NO' }}</label>
                </div>

                <div class="mb-3">
                    <label for="exampleFormControlTextarea1" class="form-label">Observaciones</label>
                    <textarea class="form-control" id="exampleFormControlTextarea1" rows="3"
                        v-model="Heuristics.OBSERVACIONH10"></textarea>
                </div>
                <button type="button" class="btn btn-primary btn-lg" @click="enviarinfo">Enviar</button>
            </div>
            <div>
    <button @click="generarPDF">Generar PDF</button>
    <br>
    <!-- se Utiliza un <iframe> para mostrar el PDF -->
    <iframe :src="pdfUrl" style="width: 100%; height: 600px;"></iframe>
  </div>
      
</template>
  
<script setup>
import { ref, onMounted, } from 'vue';
import { useRoute, useRouter } from 'vue-router'
import axios from 'axios';
import { jsPDF } from 'jspdf';
import 'jspdf-autotable';



const route = useRoute();
const router = useRouter();
const showChatbot = ref(false);

const toggleChatbot = () => {
    showChatbot.value = !showChatbot.value;
}

onMounted(() => {
    getownerInfo(route.params.idowner);
})
// Variable para controlar el estado del checkbox
const Heuristics = ref(
    {
        owner_id: 0,
        H01P01: false,
        H01P02: false,
        H01P03: false,
        H01P04: false,
        H01P05: false,
        H01P06: false,
        H01P07: false,

        H02P01: false,
        H02P02: false,
        H02P03: false,
        H02P04: false,
        H02P05: false,
        H02P06: false,
        H02P07: false,
        H02P08: false,

        H03P01: false,
        H03P02: false,
        H03P03: false,
        H03P04: false,
        H03P05: false,
        H03P06: false,

        H04P01: false,
        H04P02: false,
        H04P03: false,
        H04P04: false,
        H04P05: false,
        H04P06: false,
        H04P07: false,
        H04P08: false,
        H04P09: false,
        H04P10: false,
        H04P11: false,
        H04P12: false,
        H04P13: false,

        H05P01: false,
        H05P02: false,
        H05P03: false,
        H05P04: false,
        H05P05: false,
        H06P01: false,
        H06P02: false,
        H06P03: false,
        H07P01: false,
        H07P02: false,
        H07P03: false,
        H07P04: false,
        H07P05: false,
        H07P06: false,
        H07P07: false,
        H08P01: false,
        H08P02: false,
        H08P03: false,
        H08P04: false,
        H08P05: false,
        H08P06: false,
        H08P07: false,
        H08P08: false,
        H08P09: false,
        H08P10: false,
        H08P11: false,

        H09P01: false,
        H09P02: false,
        H09P03: false,
        H09P04: false,
        H09P05: false,
        H09P06: false,
        H10P01: false,
        H10P02: false,
        H10P03: false,
        H10P04: false,
        H10P05: false,
        H10P06: false,
        H10P07: false,
        H10P08: false,
        H10P09: false,
        OBSERVACIONH1: "",
        OBSERVACIONH2: "",
        OBSERVACIONH3: "",
        OBSERVACIONH4: "",
        OBSERVACIONH5: "",
        OBSERVACIONH6: "",
        OBSERVACIONH7: "",
        OBSERVACIONH8: "",
        OBSERVACIONH9: "",
        OBSERVACIONH10: ""
    }
)



const enviarinfo = async () => {
    console.log("pruebaenvio", route.params.idowner);

    Heuristics.value.owner_id = route.params.idowner;
    console.log(Heuristics.value);
    await axios.post("http://127.0.0.1:5000/heuristics", Heuristics.value).then(response => {
        console.log(response)
        router.push('/encuestaterminada')
    }).catch(err => {
        console.log(err)
    }
    );
}
const owner = ref({
    name: '',
    url: '',
    description: '',
});
const url = ref('');
const getownerInfo = async (id) => {
    try {
        const response = await axios.get(`http://127.0.0.1:5000/owners/${id}`);
        owner.value = response.data;
        url.value = owner.value.url;
        console.log(url.value);
    } catch (error) {
        console.log(error);
    }
}

const generarPDF = () => {
    const doc = new jsPDF();

    const aprobadoNoAprobado = (value) => {
        return value ? "Aprobado" : "No Aprobado";
    };
      // Agregar contenido al PDF
    doc.text("Resultado de la Lista de Chequeo", 10, 10);
    const data1 = [
   
        ["H01P01:", "El sistema indica la sección donde se encuentra actualmente el usuario: " + aprobadoNoAprobado (Heuristics.value.H01P01) ],
        ["H01P02:", "El sistema informa acerca del estado actual de un proceso/tarea: " + aprobadoNoAprobado ( Heuristics.value.H01P02) ],
        ["H01P03:", "La transición de un estado a otro es fácilmente perceptible: " + aprobadoNoAprobado (Heuristics.value.H01P03) ],
        ["H01P04:", "El sistema muestra claramente las reacciones a las acciones del usuario: " + aprobadoNoAprobado (Heuristics.value.H01P04)],
        ["H01P05:", "El sistema muestra claramente las reacciones a las acciones del usuario: " + aprobadoNoAprobado (Heuristics.value.H01P05) ],
        ["H01P06:", "Los tiempos de respuesta son razonables." + aprobadoNoAprobado (Heuristics.value.H01P06) ],
        ["H01P07:", "Una opción seleccionada se destaca claramente respecto a otras: " + aprobadoNoAprobado (Heuristics.value.H01P07)],
        // Agregar las observaciones al PDF
        ["Observaciones:", Heuristics.value.OBSERVACIONH1 || '']
    ];

    // Configuración de la primera tabla (data1)
    const options1 = {
        startY: 20, // Posición inicial de la tabla
        head: [["Código", "Descripción"]],
        body: data1,
        theme: 'grid' // Tema de la tabla
    };
    // Agregar la primera tabla al PDF
    doc.autoTable(options1);

    const data2 = [
        ["H02P01:", "El sistema usa palabras, frases y conceptos familiares al usuario: " + aprobadoNoAprobado(Heuristics.value.H02P01) ],
        ["H02P02:", "La información es presentada de forma simple, natural y en orden lógico: " + aprobadoNoAprobado(Heuristics.value.H02P02) ],
        ["H02P03:", "El sistema está diseñado en el idioma que indica." + aprobadoNoAprobado(Heuristics.value.H02P03) ],
        ["H02P04:", "La secuencia de pasos de los procesos sigue el modelo mental de los usuarios: " + aprobadoNoAprobado(Heuristics.value.H02P04) ],
        ["H02P05:", "El sistema utiliza metáforas y controles de interfaz que corresponden con la realidad: " + aprobadoNoAprobado(Heuristics.value.H02P05) ],
        ["H02P06:", "Las metáforas son fáciles de comprender." + aprobadoNoAprobado( Heuristics.value.H02P06)],
        ["H02P07:", "Los controles de interfaz importantes se presentan en la pantalla: " + aprobadoNoAprobado(Heuristics.value.H02P07) ],
        ["H02P08:", "En la aplicación se explican elementos complejos: " + aprobadoNoAprobado(Heuristics.value.H02P08) ],
        // Agregar las observaciones al PDF
        ["Observaciones:", Heuristics.value.OBSERVACIONH2 || '']
    ];
    const options2 = {
        startY: doc.autoTable.previous.finalY + 10, // Posición inicial de la segunda tabla (debajo de la primera)
        head: [["Código", "Descripción"]],
        body: data2,
        theme: 'grid' // Tema de la tabla
    };
    doc.autoTable(options2);
    

    const data3 = [
        ["H03P01:", "Es posible deshacer una acción cuando ésta es una función o genera alguna operación:  " +  aprobadoNoAprobado(Heuristics.value.H03P01)],
        ["H03P02:", "En caso de realizar una transacción que posee varios pasos,es posible volver a pasos anteriores del proceso para modificarlos: " + aprobadoNoAprobado(Heuristics.value.H03P02)],
        ["H03P03:", "Existe una salida de emergencia al realizar algún proceso (Cancelar desconecta, va al inicio)." + aprobadoNoAprobado(Heuristics.value.H03P03)],
        ["H03P04:", "No se inician de forma automática acciones que no han sido seleccionadas por el usuario. Por ejemplo, la reproducción de un vídeo: " + aprobadoNoAprobado(Heuristics.value.H03P04)],
        ["H03P05:", "Es posible guardar la información relacionada a una transacción, sea exitosa o no: " + aprobadoNoAprobado(Heuristics.value.H03P05)],
        ["H03P06:", "Existe un vínculo para regresar a la página de inicio: " + aprobadoNoAprobado(Heuristics.value.H03P06)],
      
        // Agregar las observaciones al PDF
        ["Observaciones:", Heuristics.value.OBSERVACIONH3 || '']
    ];
    const options3 = {
        startY: doc.autoTable.previous.finalY + 10, 
        head: [["Código", "Descripción"]],
        body: data3,
        theme: 'grid' 
    };
    doc.autoTable(options3);


    const data4= [
        ["H04P01:", "Las etiquetas de vínculos tienen nombres iguales que lostítulos de la página a los que redirige: " + aprobadoNoAprobado(Heuristics.value.H04P01) ],
        ["H04P02:", "Las mismas acciones llevan a los mismos resultados. Por ejemplo, al ingresar a una sección desde distintas partes del sistema, éstas se dirigen a la misma: " + aprobadoNoAprobado(Heuristics.value.H04P02)],
        ["H04P03:", "Los elementos utilizados son similares en todo el sistema: " + aprobadoNoAprobado( Heuristics.value.H04P03)],
        ["H04P04:", "Los controles de interfaz de diferentes pantallas se emplean siempre del mismo modo:  " + aprobadoNoAprobado(Heuristics.value.H04P04)],
        ["H04P05:", "El uso del vocabulario es consistente en todo el sistema: " + aprobadoNoAprobado(Heuristics.value.H04P05)],
        ["H04P06:", "La misma información se muestra de la misma forma en todo el sistema: " + aprobadoNoAprobado(Heuristics.value.H04P06)],
        ["H04P07:", "La información está estructurada de forma similar en todo el sistema: " + aprobadoNoAprobado(Heuristics.value.H04P07)],
        ["H04P08:", "Las interfaces que conforman el sistema tienen un aspecto visual coherente:  " + aprobadoNoAprobado(Heuristics.value.H04P08)],
        ["H04P09:", "En situaciones similares se repiten secuencias de acciones:  " + aprobadoNoAprobado(Heuristics.value.H04P09)],
        ["H04P10:", "Los símbolos utilizados son comprensibles y facilitan la interacción con el sistema:  " + aprobadoNoAprobado(Heuristics.value.H04P10)],
        ["H04P11:", "Se usan colores estándares para vínculos (rojo para advertencia, verde para acción exitosa):  " + aprobadoNoAprobado(Heuristics.value.H04P11)],
        ["H04P12:", "Se siguen los estándares establecidos para los símbolos utilizados (equis para cancelar, etc.): " + aprobadoNoAprobado(Heuristics.value.H04P12)],
        ["H04P13:", "La ubicación de las barras de navegación, herramientas de búsquedas y controles (botones) siguen los estándares comunes establecidos: " + aprobadoNoAprobado(Heuristics.value.H04P13)],
        // Agregar las observaciones al PDF
        ["Observaciones:", Heuristics.value.OBSERVACIONH4 || '']
    ];
      const options4 = {
        startY: doc.autoTable.previous.finalY + 10, 
        head: [["Código", "Descripción"]],
        body: data4,
        theme: 'grid' 
    };
    doc.autoTable(options4);


    const data5 = [
        ["H05P01:", "Se le pide confirmación al usuario antes de realizar una acción crítica (eliminar, aceptar, etc):  " + aprobadoNoAprobado(Heuristics.value.H05P01) ],
        ["H05P02:", "El sistema provee mensajes fáciles de entender que previenen posibles errores: " + aprobadoNoAprobado( Heuristics.value.H05P02)],
        ["H05P03:", "El sistema ofrece métodos de selección a los usuarios como alternativas para el ingreso datos: " + aprobadoNoAprobado(Heuristics.value.H05P03) ],
        ["H05P04:", "los campos de entrada de datos contienen valores por defecto cuando corresponde: " + aprobadoNoAprobado( Heuristics.value.H05P05) ],
        ["H05P05:", "Todos los datos de entrada son validados: " + aprobadoNoAprobado( Heuristics.value.H05P05)],
      
        // Agregar las observaciones al PDF
        ["Observaciones:", Heuristics.value.OBSERVACIONH5 || '']
    ];
    const options5 = {
        startY: doc.autoTable.previous.finalY + 10, 
        head: [["Código", "Descripción"]],
        body: data5,
        theme: 'grid' 
    };
    doc.autoTable(options5);


    const data6 = [
        ["H06P01:", "Las opciones y/o funciones son fáciles de encontrar:  " + aprobadoNoAprobado( Heuristics.value.H06P01)],
        ["H06P02:", "Los principales controles de interfaz, están siempre disponibles, visibles y son de fácil acceso: " + aprobadoNoAprobado(Heuristics.value.H06P02)],
        ["H06P03:", "Los campos de entrada de datos ya llenos mantienen la información siempre recordada: " + aprobadoNoAprobado(Heuristics.value.H06P03)],
        // Agregar las observaciones al PDF
        ["Observaciones:", Heuristics.value.OBSERVACIONH6 || '']
    ];
    const options6 = {
        startY: doc.autoTable.previous.finalY + 10,
        head: [["Código", "Descripción"]],
        body: data6,
        theme: 'grid' 
    };
    doc.autoTable(options6);


    const data7 = [
        ["H07P01:", "Existen atajos para realizar tareas frecuentes:  " + aprobadoNoAprobado(Heuristics.value.H07P01)],
        ["H07P02:", "El sistema es personalizable, de acuerdo a las necesidades,características,  preferencias personales, etc., de los usuarios: " + aprobadoNoAprobado(Heuristics.value.H07P02)],
        ["H07P03:", "El sistema no pide volver a ingresar información que ya ha sido solicitada con anterioridad: " + aprobadoNoAprobado(Heuristics.value.H07P03)],
        ["H07P04:", "Las acciones que realiza el usuario toman mucho tiempo. " + aprobadoNoAprobado(Heuristics.value.H03P04)],
        ["H07P05:", "El sistema informa al usuario si la ejecución de una acción requiere mucho tiempo: " + aprobadoNoAprobado(Heuristics.value.H07P05)],
        ["H07P06:", "Al rellenar un campo, las opciones disponibles se pueden seleccionar sin tener  que escribirlas: " + aprobadoNoAprobado(Heuristics.value.H07P06)],
        ["H07P07:", "La herramienta de búsqueda es visible en todo el sistema: " + aprobadoNoAprobado(Heuristics.value.H07P07)],
        // Agregar las observaciones al PDF
        // eslint-disable-next-line vue/no-ref-as-operand
        ["Observaciones:", Heuristics.OBSERVACIONH7 || '']
    ];
    const options7 = {
        startY: doc.autoTable.previous.finalY + 10, 
        head: [["Código", "Descripción"]],
        body: data7,
        theme: 'grid' 
    };
    doc.autoTable(options7);


    const data8 = [
        ["H08P01:", "La interfaz del sistema es simple: " + aprobadoNoAprobado(Heuristics.value.H08P01)],
        ["H08P02:", "La interfaz del sistema está sobrecargada de información y elementos que distraen al usuario:  " + aprobadoNoAprobado(Heuristics.value.H08P02)],
        ["H08P03:", "Las alternativas que el usuario necesita para realizar una tarea están visibles: " +aprobadoNoAprobado(Heuristics.value.H08P03)],
        ["H08P04:", "La información presentada es simple, concisa y clara: " + aprobadoNoAprobado(Heuristics.value.H08P04)],
        ["H08P05:", "La información visible es suficiente para realizar alguna acción: " + aprobadoNoAprobado(Heuristics.value.H08P05)],
        ["H08P06:", "Hay iconos o elementos gráficos abstractos: " + aprobadoNoAprobado(Heuristics.value.H08P06)],
        ["H08P07:", "Hay iconos, controles, menús, gráficos, textos u otros elementos redundantes: " + aprobadoNoAprobado(Heuristics.value.H08P07)],
        ["H08P08:", "Hay elementos exclusivamente ornamentales: " + aprobadoNoAprobado(Heuristics.value.H08P08)],
        ["H08P09:", "El sistema presenta información repetida:  " + aprobadoNoAprobado(Heuristics.value.H08P09)],
        ["H08P010:","Los colores utilizados dan un contraste adecuado: " + aprobadoNoAprobado(Heuristics.value.H08P10)],
        ["H08P011", "Los elementos/secciones del sistema están distribuidos correctamente en todo el sistema: " + aprobadoNoAprobado(Heuristics.value.H08P11)],
        // Agregar las observaciones al PDF
        ["Observaciones:", Heuristics.value.OBSERVACIONH8 || '']
    ];
    const options8 = {
        startY: doc.autoTable.previous.finalY + 10, 
        head: [["Código", "Descripción"]],
        body: data8,
        theme: 'grid'
    };
    doc.autoTable(options8);


    const data9 = [
        ["H09P01:", "Los mensajes de error son compresibles, escritos en lenguaje común, sin códigos o palabras técnicas:  " + aprobadoNoAprobado(Heuristics.value.H09P01)],
        ["H09P02:", "Los mensajes de error indican la causa del error: " + aprobadoNoAprobado( Heuristics.value.H09P02)],
        ["H09P03:", "Los mensajes de error orientan al usuario para solucion  el problema: " + aprobadoNoAprobado(Heuristics.value.H09P03)],
        ["H09P04:", "Los mensajes de error utilizan una terminología y diseño consistentes:  " + aprobadoNoAprobado(Heuristics.value.H09P04)],
        ["H09P05:", "Los mensajes de error están escritos en una forma constructiva, de tal manera que no atribuyen la culpa ni ofenden al usuario: " + aprobadoNoAprobado(Heuristics.value.H09P05)],
        ["H09P06:", "Los mensajes de error usan palabras violentas u hostiles: " + aprobadoNoAprobado(Heuristics.value.H09P06)],
        // Agregar las observaciones al PDF
        ["Observaciones:", Heuristics.value.OBSERVACIONH9 || '']
    ];
    const options9 = {
        startY: doc.autoTable.previous.finalY + 10, 
        head: [["Código", "Descripción"]],
        body: data9,
        theme: 'grid' 
    };
    doc.autoTable(options9);


    const data10 = [
        ["H10P01:", "El sistema ofrece una ayuda clara y simple. " + aprobadoNoAprobado(Heuristics.value.H10P01)],
        ["H10P02:", "La ayuda esta expresada en el lenguaje del usuario, libre de jergas y modismos: " + aprobadoNoAprobado(Heuristics.value.H10P02)],
        ["H10P03:", "La ayuda es fácil de encontrar, entender y aplicar: " + aprobadoNoAprobado(Heuristics.value.H10P03)],
        ["H10P04:", "La ayuda siempre está visible y disponible: " + aprobadoNoAprobado(Heuristics.value.H10P04)],
        ["H10P05:", "La estructura de la información de la ayuda se distingue fácilmente: " +aprobadoNoAprobado(Heuristics.value.H10P05) ],
        ["H10P06:", "Las instrucciones de ayuda siguen la secuencia de acciones a realizar por el  usuario para alcanzar una tarea: " + aprobadoNoAprobado(Heuristics.value.H10P06)],
        ["H10P07:", "La interfaz de la ayuda es consistente con la interfaz de todo el sistema: " + aprobadoNoAprobado(Heuristics.value.H10P07)],
        ["H10P08:", "En la ayuda la información es fácil de encontrar: " + aprobadoNoAprobado(Heuristics.value.H10P08)],
        ["H10P09:", "En el sistema existe ayuda contextual que guía al usuario respecto al uso de los elementos: " + aprobadoNoAprobado(Heuristics.value.H10P09)],
        // Agregar las observaciones al PDF
        ["Observaciones:", Heuristics.value.OBSERVACIONH10 || '']
    ];
    const options10 = {
        startY: doc.autoTable.previous.finalY + 10, 
        head: [["Código", "Descripción"]],
        body: data10,
        theme: 'grid' 
    };
    doc.autoTable(options10);

    // Crear una URL para el Blob
    const pdfBlob = doc.output('blob');
    const pdfUrl = URL.createObjectURL(pdfBlob);

    // Abrir el PDF en una nueva pestaña
    const eventoPDF = new CustomEvent('pdf-generado', { detail: pdfUrl });
    window.dispatchEvent(eventoPDF);
};
</script>
<style>
    /* Estilos para el contenedor del chatbot */
    .chatbot-container {
        width: 350px;
        height: 430px;
        border: 1px solid #200d55;
        border-radius: 5px;
        overflow: hidden;
        position: fixed;
        right: 20px; 
        top: 50%; 
        transform: translateY(-50%);
        z-index: 9999; 
    }
    /* Estilos para el iframe dentro del contenedor del chatbot */
    .chatbot-container iframe {
        width: 100%;
        height: 100%;
        border: 0;
    }
   .chat-icon {
    position: fixed;
    right: 20px; 
    bottom: 20px; 
    font-size: 24px; 
    cursor: pointer;
    z-index: 9999; 
}
.chat-icon {
    position: fixed;
    bottom: 20px;
    right: 20px;
    cursor: pointer;
}
.chat-icon img {
    width: 50px; 
    height: 50px; 
}
</style>
